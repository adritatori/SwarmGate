"""Run every scenario x every mode x N seeds and write results.

  python -m oor.run --seeds 10                      # scripted worst-case agents
  python -m oor.run --seeds 5 --policy ollama --model qwen2.5:3b
"""
import argparse
import csv
import json
import os
import platform
import statistics
import time
from collections import defaultdict

from .gateway import MODES
from .policy import LLMPolicy, NaivePolicy
from .scenarios import ATTACKS, BENIGN, Ctx


def make_policy(args, seed):
    if args.policy == "naive":
        return NaivePolicy()
    from .llm import OllamaClient
    return LLMPolicy(OllamaClient(args.model, args.ollama_url, temperature=args.temperature), seed=seed)


def template_of(scenario, seed):
    """Which attack text a run used (the scenarios pick it by seed)."""
    from .scenarios import INJECTIONS, POISONED_DESCRIPTIONS
    if scenario in ("a9_upward_injection", "a10_taint_laundering"):
        return f"inj{seed % len(INJECTIONS)}"
    if scenario == "a2_card_poison":
        return f"card{seed % len(POISONED_DESCRIPTIONS)}"
    return ""


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=10)
    p.add_argument("--policy", choices=["naive", "ollama"], default="naive")
    p.add_argument("--model", default="qwen2.5:3b")
    p.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "http://localhost:11434"))
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--out", default=os.path.join("results", "v2"))
    args = p.parse_args(argv)

    tag = args.policy if args.policy == "naive" else f"ollama-{args.model.replace(':', '_')}"
    if args.policy != "naive" and args.temperature:
        tag += f"_T{args.temperature:g}"
    out = os.path.join(args.out, tag)
    os.makedirs(os.path.join(out, "logs"), exist_ok=True)

    rows, timing = [], defaultdict(list)
    llm_f = open(os.path.join(out, "llm_transcripts.jsonl"), "w", encoding="utf-8")
    audit_f = open(os.path.join(out, "all_gateway_logs.jsonl"), "w", encoding="utf-8")
    t_start = time.time()
    for kind, scen_list in (("attack", ATTACKS), ("benign", BENIGN)):
        for fn in scen_list:
            for mode in MODES:
                for seed in range(args.seeds):
                    ctx = Ctx(mode, seed, make_policy(args, seed))
                    try:
                        success, detail = fn(ctx)
                        error = ""
                    except Exception as e:  # a crash is recorded, never hidden
                        success, detail, error = None, "", f"{type(e).__name__}: {e}"
                    run_id = f"{fn.__name__}|{mode}|{seed}"
                    tmpl = template_of(fn.__name__, seed)
                    rows.append({"kind": kind, "scenario": fn.__name__, "mode": mode, "seed": seed,
                                 "template": tmpl, "policy": tag, "success": success, "detail": detail,
                                 "error": error})
                    client = getattr(ctx.policy, "client", None)
                    if client is not None:
                        for call in client.pop_trace():
                            llm_f.write(json.dumps({"run_id": run_id, "template": tmpl, **call}) + "\n")
                    if ctx.gw.external:
                        recs = [e["record"] for e in ctx.gw.audit.entries]
                    else:
                        recs = ctx.gw.investigator_records()
                    for rec in recs:
                        audit_f.write(json.dumps({"run_id": run_id, **rec}, default=str) + "\n")
                    timing[mode].extend(ctx.gw.timing)
                    if seed == 0:  # keep one example log per scenario/mode
                        base = os.path.join(out, "logs", f"{fn.__name__}__{mode.replace('+', '_')}")
                        if ctx.gw.external:
                            ctx.gw.audit.dump_jsonl(base + "__gateway_audit.jsonl")
                        else:
                            with open(base + "__agent_written_logs.json", "w") as f:
                                json.dump(ctx.gw.agent_logs, f, indent=1)
                    print(f"{kind:6} {fn.__name__:22} {mode:15} seed={seed:<3} "
                          f"{'ERROR' if error else ('WIN ' if success else 'fail') if kind == 'attack' else ('done' if success else 'FAILED')}"
                          f"  {error or detail}")

    llm_f.close()
    audit_f.close()
    with open(os.path.join(out, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    write_summary(rows, timing, out, args, time.time() - t_start)
    print(f"\nWrote {out}/results.csv and {out}/summary.md")


def write_summary(rows, timing, out, args, elapsed):
    def rate(kind, scen, mode):
        xs = [r["success"] for r in rows if r["kind"] == kind and r["scenario"] == scen and r["mode"] == mode]
        ok = [x for x in xs if x is not None]
        errs = len(xs) - len(ok)
        s = f"{sum(ok)}/{len(ok)}"
        return s + (f" ({errs} err)" if errs else "")

    lines = [f"# Results ({rows[0]['policy']}, {args.seeds} seeds per cell)", "",
             f"Run on {platform.platform()} in {elapsed:.1f}s.", "",
             "## Attack success (attacker wins / runs). Lower is better.", "",
             "| attack | " + " | ".join(MODES) + " |", "|---" * (len(MODES) + 1) + "|"]
    for fn in ATTACKS:
        lines.append(f"| {fn.__name__} | " + " | ".join(rate("attack", fn.__name__, m) for m in MODES) + " |")
    lines += ["", "## Normal work completed (done / runs). Higher is better.", "",
              "| task | " + " | ".join(MODES) + " |", "|---" * (len(MODES) + 1) + "|"]
    for fn in BENIGN:
        lines.append(f"| {fn.__name__} | " + " | ".join(rate("benign", fn.__name__, m) for m in MODES) + " |")
    lines += ["", "## Gateway check cost (signature + registry + replay check)", ""]
    for m in MODES:
        t = timing[m]
        if t:
            lines.append(f"- {m}: mean {statistics.mean(t) * 1e3:.3f} ms, "
                         f"p95 {sorted(t)[int(0.95 * (len(t) - 1))] * 1e3:.3f} ms over {len(t)} checks")
        else:
            lines.append(f"- {m}: no checks (agents enforce themselves)")
    lines += ["", "## One example detail per attack (seed 0)", ""]
    for r in rows:
        if r["seed"] == 0 and r["kind"] == "attack":
            lines.append(f"- {r['scenario']} / {r['mode']}: {r['error'] or r['detail']}")
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
