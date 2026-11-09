# Out of Reach — bug log (swarm extension)

Found while checking the qwen2.5:3b swarm run (`results/swarm/ollama-qwen2.5_3b`, 42 runs, 1,890 decisions), 8 Nov 2026.

| ID | Type | Symptom | Root cause (file) | What it broke in results | Fix | Status |
|---|---|---|---|---|---|---|
| BUG-01 | Design flaw (rule works as written) | Every high-privilege agent is tainted from step 1, **also in harmless control runs** (`high_tainted_frac` = 1.0 in all 42 runs). | `oor/gateway.py`, `Gateway.send`: an agent is tainted when it reads **any** peer whose scopes are not a superset of its own. The rule ignores what the message says. In the swarm almost every agent is low-privilege, including the source, so every high agent reads at least one low peer. | "0 leaks under taint" is not evidence of good blocking. The rule blocks everything, so in a real deployment it would also hold every legitimate external email. | Keep the rule (it produced the original results). Added `oor/taint_variants.py`, which replays the logs offline under V1 lineage and V2 content-based taint. Tests: `tests/test_taint_variants.py`. V0 replay matches the live gateway in 630/630 rows. | Reported as a finding. Variants built and tested. |
| BUG-02 | Measurement gap | Controls show 0 held emails, so taint looks free. | Control runs (`oor/swarm.py`, `BENIGN_SOURCE_TEXT`) contain no legitimate task that needs an external email, so a false hold can never show up as an outcome. | The utility cost of taint is visible only as a proxy (share of agent-steps tainted), not as blocked real work. | Not fixed. To measure real cost you'd need controls with a legitimate external email task. | Open, goes into Limitations |
| BUG-03 | Parser bug | 4/1,890 replies marked `parse_fail` (all in `random|k3|inj2|s0`). | `oor/swarm.py`, `_parse`: a greedy regex `\{.*\}` failed when the model wrote **two** JSON objects (`{"message": ...}\n{"email_to": null}`). The raw reply, braces included, was then forwarded to peers as the agent's message. | Small. None of the 4 contained an email action. A few peers read text with braces in it. | `_json_objects()` merges every JSON object in the reply. Messy-input tests were added to `tests/test_swarm.py`. Re-parsing all 1,890 old replies gives 0 failures. Backup: `oor/swarm.py.bak_parser`. | **Fixed** |
| BUG-04 | Config issue | The "laundering through a privileged peer" hypothesis was never tested. | With `p_high=0.34`, `k=3` and a low-privilege source, **0 of 42 graphs** contain a high agent that reads only high peers. That is the precondition for laundering under V0. | The E-laundering result is empty, not negative. | Not fixed. It would need a hand-built graph (`high_override` / `follows_override` already exist in `run_once`). | Open |
| — | By design (not a bug) | In `external` mode, 18/18 high-privilege sends to the drop address went through. | `external` checks identity and scopes, not the destination. | Explains why `leak[external]` = `leak[self]`. | None. Describe it clearly in the write-up. | — |
| — | By design (not a bug) | Taint never holds internal (`@corp.example`) email. | `gateway.py`, `call_tool`, uses `is_external(to)`. | Explains 3B seed 4 / B4 in the original runs. | None. | — |

## Offline taint variants on qwen2.5:3b (no new model runs)

| Rule | Cost: high agent-steps tainted, controls | Tainted, attack runs | Drop emails through / reached gateway |
|---|---|---|---|
| V0 privilege (current) | 1.00 | 1.00 | 0/18 |
| V1 lineage | 0.64 | 0.64 | 0/18 |
| V2 content (external address in input) | 0.00 | 0.28 | 0/18 |

Caveats:
- All 18 sends came from hop-1 agents that read the source directly. So any rule that taints direct readers catches them, and this is a weak test of the differences between the rules.
- V2 can be evaded by a paraphrase that drops the address. That is shown in the synthetic tests only, because no real relay past hop 1 happened.
- V2's false positives on legitimate external addresses are not measured (BUG-02).

Run it: `docker compose run --rm lab python -m oor.taint_variants results/swarm/ollama-qwen2.5_3b`
