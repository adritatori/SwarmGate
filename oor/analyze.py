"""Analyse saved logs. Never re-runs anything.

Reads   results/swarm/<policy>/{runs.csv,decisions.csv}
        results/<policy>/results.csv and results/v2/<policy>/results.csv (A1-A10 runs)
Writes  results/analysis/ : summary.md + one CSV per table + PNG figures

  python -m oor.analyze
  python -m oor.analyze --results results --out results/analysis
"""
import argparse
import glob
import itertools
import json
import math
import os

import pandas as pd

MODES = ["self", "external", "external+taint"]


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def rate_cols(df, col):
    k, n = int(df[col].sum()), int(df[col].count())
    lo, hi = wilson(k, n)
    return pd.Series({"hits": k, "n": n, "rate": k / n if n else float("nan"), "ci_lo": lo, "ci_hi": hi})


def to_bool(s):
    return s.astype(str).str.lower().isin(["true", "1"])


def load_swarm_with_policy(root):
    runs, decs = [], []
    for d in sorted(glob.glob(os.path.join(root, "swarm", "*"))):
        if not os.path.exists(os.path.join(d, "runs.csv")):
            continue
        r = pd.read_csv(os.path.join(d, "runs.csv"))
        x = pd.read_csv(os.path.join(d, "decisions.csv"))
        x["policy"] = r["policy"].iloc[0] if len(r) else os.path.basename(d)
        runs.append(r)
        decs.append(x)
    if not runs:
        return None, None
    r, d = pd.concat(runs, ignore_index=True), pd.concat(decs, ignore_index=True)
    for c in ["control"] + [c for c in r.columns if c.startswith("leak[")]:
        r[c] = to_bool(r[c])
    d["control"] = d["template"].eq("control")
    for c in ["high", "infected_out", "acted_drop", "parse_ok", "tainted[external+taint]"]:
        d[c] = to_bool(d[c])
    return r, d


def md_table(df, floatfmt=".2f"):
    df = df.copy()
    for c in df.columns:
        if df[c].dtype.kind == "f" and df[c].dropna().map(float.is_integer).all() and c not in ("rate",):
            df[c] = df[c].map(lambda v: "" if pd.isna(v) else str(int(v)))
        elif df[c].dtype.kind == "f":
            df[c] = df[c].map(lambda v: "" if pd.isna(v) else format(v, floatfmt))
    head = "| " + " | ".join(map(str, df.columns)) + " |"
    sep = "|" + "---|" * len(df.columns)
    rows = ["| " + " | ".join(map(str, row)) + " |" for row in df.itertuples(index=False)]
    return "\n".join([head, sep, *rows])


def swarm_tables(r, d):
    t = {}
    att, datt = r[~r["control"]], d[~d["control"]]

    # E3: spread per hop (agent ever relayed the address), reachable agents only
    maxstep = datt.groupby("run_id")["step"].transform("max")
    ever = (datt[datt["hop"].notna() & (datt["hop"] <= maxstep)]
            .groupby(["policy", "topology", "k", "run_id", "agent", "hop"])["infected_out"].any().reset_index())
    t["spread_by_hop"] = (ever.groupby(["policy", "topology", "k", "hop"])
                          .apply(lambda g: rate_cols(g, "infected_out"), include_groups=False).reset_index())

    # E2: dose -> response
    t["dose_response"] = (datt.groupby(["policy", "dose"])
                          .apply(lambda g: pd.concat([rate_cols(g, "infected_out").add_prefix("relay_"),
                                                      rate_cols(g, "acted_drop").add_prefix("act_")]),
                                 include_groups=False).reset_index())
    t["dose_response_by_priv"] = (datt.groupby(["policy", "high", "dose"])
                                  .apply(lambda g: rate_cols(g, "acted_drop"), include_groups=False).reset_index())

    # Containment per gateway mode
    rows = []
    for (pol, top), g in att.groupby(["policy", "topology"]):
        row = {"policy": pol, "topology": top, "runs": len(g),
               "mean_frac_infected": g["frac_infected"].mean()}
        for m in MODES:
            row[f"leak_rate[{m}]"] = g[f"leak[{m}]"].mean()
            row[f"held_total[{m}]"] = int(g[f"held[{m}]"].sum())
        row["laundered_runs"] = int((g["senders_through_taint"].map(lambda s: len(json.loads(s)) > 0)).sum())
        row["lowpriv_attempts"] = int(g["n_act_drop_lowpriv"].sum())
        rows.append(row)
    t["containment"] = pd.DataFrame(rows)

    # Utility cost proxy: share of high-privilege agents the taint rule would block, harmless runs
    ctrl = r[r["control"]]
    if len(ctrl):
        t["taint_cost_control"] = (ctrl.groupby(["policy", "topology", "k"])
                                   .agg(runs=("run_id", "count"), high_tainted_frac=("high_tainted_frac", "mean"),
                                        false_emails=("n_email_any", "sum")).reset_index())

    # Which injection template spreads most
    t["by_template"] = (att.groupby(["policy", "template"])
                        .agg(runs=("run_id", "count"), mean_frac_infected=("frac_infected", "mean"),
                             leak_rate_external=("leak[external]", "mean"),
                             leak_rate_taint=("leak[external+taint]", "mean")).reset_index())

    # Parse failures (model did not answer in the requested format)
    t["parse"] = d.groupby("policy").agg(decisions=("parse_ok", "count"),
                                         parse_fail_rate=("parse_ok", lambda s: 1 - s.mean())).reset_index()

    # E1: error overlap between policies, on step-1 decisions (identical inputs across policies)
    s1 = datt[datt["step"] == 1].copy()
    s1["key"] = s1["run_id"] + "|" + s1["agent"]
    pols = sorted(s1["policy"].unique())
    rows = []
    for a, b in itertools.combinations(pols, 2):
        A = s1[s1["policy"] == a].set_index("key")
        B = s1[s1["policy"] == b].set_index("key")
        common = A.index.intersection(B.index)
        if not len(common):
            continue
        for col in ("infected_out", "acted_drop"):
            x, y = A.loc[common, col], B.loc[common, col]
            both, either = int((x & y).sum()), int((x | y).sum())
            rows.append({"policy_a": a, "policy_b": b, "behaviour": col, "decisions": len(common),
                         "a_rate": x.mean(), "b_rate": y.mean(), "agree": (x == y).mean(),
                         "jaccard_of_failures": both / either if either else float("nan")})
    if rows:
        t["error_overlap_step1"] = pd.DataFrame(rows)
    return t


def attack_tables(root):
    frames = []
    for f in glob.glob(os.path.join(root, "*", "results.csv")) + glob.glob(os.path.join(root, "v2", "*", "results.csv")):
        x = pd.read_csv(f)
        x["source_file"] = os.path.relpath(f, root)
        frames.append(x)
    if not frames:
        return {}
    a = pd.concat(frames, ignore_index=True)
    a = a[a["scenario"].isin(["a2_card_poison", "a9_upward_injection", "a10_taint_laundering"])]
    a = a[~a["policy"].eq("naive")]
    if a.empty:
        return {}
    a["success"] = to_bool(a["success"])
    if "template" not in a or a["template"].isna().all():
        n = {"a2_card_poison": 4, "a9_upward_injection": 6, "a10_taint_laundering": 6}
        a["template"] = [("card" if s == "a2_card_poison" else "inj") + str(int(sd) % n[s])
                         for s, sd in zip(a["scenario"], a["seed"])]
    a = a.drop_duplicates(["policy", "scenario", "mode", "seed", "source_file"])
    out = {"model_by_template": a.pivot_table(index=["scenario", "mode", "template"], columns="policy",
                                              values="success", aggfunc="mean").reset_index()}
    rows = []
    sub = a[a["mode"] == "self"]
    for scen, g in sub.groupby("scenario"):
        pols = sorted(g["policy"].unique())
        for p1, p2 in itertools.combinations(pols, 2):
            x = set(g[(g["policy"] == p1) & g["success"]]["seed"])
            y = set(g[(g["policy"] == p2) & g["success"]]["seed"])
            rows.append({"scenario": scen, "policy_a": p1, "policy_b": p2, "fooled_a": len(x), "fooled_b": len(y),
                         "fooled_both": len(x & y), "jaccard": len(x & y) / len(x | y) if x | y else float("nan")})
    if rows:
        out["model_error_overlap"] = pd.DataFrame(rows)
    return out


def figures(t, out):
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/mpl")   # container filesystem is read-only
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []
    made = []
    if "spread_by_hop" in t:
        s = t["spread_by_hop"]
        tops = sorted(s["topology"].unique())
        fig, axes = plt.subplots(1, len(tops), figsize=(4 * len(tops), 3.2), sharey=True, squeeze=False)
        for ax, top in zip(axes[0], tops):
            for (pol, k), g in s[s["topology"] == top].groupby(["policy", "k"]):
                g = g.sort_values("hop")
                ax.errorbar(g["hop"], g["rate"], yerr=[(g["rate"] - g["ci_lo"]).clip(lower=0), (g["ci_hi"] - g["rate"]).clip(lower=0)],
                            marker="o", capsize=2, label=f"{pol} k={k}")
            ax.set_title(top)
            ax.set_xlabel("hops from source")
            ax.set_ylim(-0.05, 1.05)
        axes[0][0].set_ylabel("share of agents relaying")
        axes[0][-1].legend(fontsize=7)
        fig.tight_layout()
        p = os.path.join(out, "fig_spread_by_hop.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        made.append(p)
    if "dose_response" in t:
        s = t["dose_response"]
        fig, ax = plt.subplots(figsize=(4.5, 3.2))
        for pol, g in s.groupby("policy"):
            g = g.sort_values("dose")
            ax.errorbar(g["dose"], g["act_rate"], yerr=[(g["act_rate"] - g["act_ci_lo"]).clip(lower=0), (g["act_ci_hi"] - g["act_rate"]).clip(lower=0)],
                        marker="o", capsize=2, label=pol)
        ax.set_xlabel("dose (inputs carrying the address)")
        ax.set_ylabel("P(agent chooses to email it)")
        ax.set_ylim(-0.05, 1.05)
        ax.legend(fontsize=7)
        fig.tight_layout()
        p = os.path.join(out, "fig_dose_response.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        made.append(p)
    if "containment" in t:
        c = t["containment"]
        fig, ax = plt.subplots(figsize=(6, 3.2))
        labels = c["policy"] + "\n" + c["topology"]
        w = 0.27
        for i, m in enumerate(MODES):
            ax.bar([x + (i - 1) * w for x in range(len(c))], c[f"leak_rate[{m}]"], w, label=m)
        ax.set_xticks(range(len(c)))
        ax.set_xticklabels(labels, fontsize=6)
        ax.set_ylabel("runs with a data leak")
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=7)
        fig.tight_layout()
        p = os.path.join(out, "fig_containment_by_mode.png")
        fig.savefig(p, dpi=150)
        plt.close(fig)
        made.append(p)
    return made


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="results")
    p.add_argument("--out", default=os.path.join("results", "analysis"))
    args = p.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    tables = {}
    r, d = load_swarm_with_policy(args.results)
    if r is not None:
        tables.update(swarm_tables(r, d))
    tables.update(attack_tables(args.results))

    lines = ["# Analysis (generated by oor/analyze.py from saved logs)", ""]
    notes = {
        "spread_by_hop": "E3 spread per hop: share of reachable agents that ever relayed the drop address, by hop distance.",
        "dose_response": "E2 response curve: probability of relaying / acting, by how many inputs carried the address.",
        "dose_response_by_priv": "Acting rate by privilege. Low-privilege 'acts' are intent only; the gateway denies them.",
        "containment": "Runs with a real data leak, per gateway mode. laundered_runs = taint mode leaked via an untainted high-privilege agent.",
        "taint_cost_control": "Harmless runs: share of high-privilege agents the taint rule would block (utility cost proxy).",
        "by_template": "Which existing injection template spreads most.",
        "parse": "How often the model's reply did not follow the JSON format.",
        "error_overlap_step1": "E1 error overlap between policies on step-1 decisions (same inputs). High Jaccard = correlated failures.",
        "model_by_template": "A2/A9/A10 success by template and model (from the A1-A10 runs).",
        "model_error_overlap": "E1 for A2/A9/A10: do the two models fail on the same variants?",
    }
    for name, df in tables.items():
        df.to_csv(os.path.join(args.out, f"{name}.csv"), index=False)
        lines += [f"## {name}", "", notes.get(name, ""), "", md_table(df), ""]
    figs = figures(tables, args.out)
    lines += ["## Figures", ""] + [f"- {os.path.basename(f)}" for f in figs]
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(tables)} tables and {len(figs)} figures to {args.out}")


if __name__ == "__main__":
    main()
