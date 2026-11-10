#!/usr/bin/env python3
"""
make_results.py - turn the graded answers into the paper's tables and charts.

Reads  : grading/graded_calls.csv, grading/stability_summary.csv       (made by grade_runs.py)
Writes : results_tables/*.csv        the full tables
         results_tables/*.tex        compact LaTeX versions (booktabs) ready for the paper
         results_tables/figures/     3 charts as PNG and PDF (needs matplotlib)

Tables (the complete condition = the 15 services with a known version):
  table1_overall_t0          per model and prompt, the temperature-0 run
  table2_overall_t07         per model and prompt, the three temperature-0.7 runs pooled, with stability
  table3_by_role_t0          per model, prompt and role (old / mid / latest), temperature 0
  table4_incomplete_input    the services scanned without a version (abstention is the right answer)
  table5_prompt_c_choices    what the models picked from the candidate list of prompt (c)
  table6_sensitivity_valid_only   table 1 again, using only answers whose JSON was valid (the main tables also
                                  grade ids found by regex in broken answers)
Rows named baseline_* are the non-AI baselines (baseline_cpe.py), graded the same way as the models.

Run from the nmap-lab folder:
    python make_results.py
"""

import argparse
import collections
import csv
import os
import sys

from grade_runs import METRIC_FIELDS, load_calls_csv, metrics, read_csv, write_csv

MODEL_ORDER = ["llama3.2:3b", "phi4-mini", "qwen3.5:4b", "baseline_raw_cpe", "baseline_corrected_cpe"]
PROMPT_ORDER = ["a", "b", "c", "-"]
ROLE_ORDER = ["old", "mid", "latest"]
PROMPT_NAME = {"a": "(a) direct", "b": "(b) abstain", "c": "(c) shortlist", "-": "-"}
MODEL_LABEL = {"baseline_raw_cpe": "Baseline: raw CPE", "baseline_corrected_cpe": "Baseline: corrected CPE"}

PCT = {"invalid_output_rate", "fabricated_rate", "real_but_wrong_rate", "abstention_rate", "empty_answer_rate",
       "clean_service_ok_rate", "answers_with_citation_rate"}
TWO_DEC = {"precision", "recall", "recall_critical", "mean_jaccard"}
ONE_DEC = {"avg_cited_per_answer"}


def sort_key(row):
    m = row.get("model", "")
    p = row.get("prompt", "-")
    r = row.get("role", "")
    return (MODEL_ORDER.index(m) if m in MODEL_ORDER else 99, PROMPT_ORDER.index(p) if p in PROMPT_ORDER else 99,
            ROLE_ORDER.index(r) if r in ROLE_ORDER else 99)


def fmt(col, v):
    if v is None or v == "":
        return "--"
    if col in PCT:
        return f"{100 * float(v):.1f}\\%"
    if col in TWO_DEC:
        return f"{float(v):.2f}"
    if col in ONE_DEC:
        return f"{float(v):.1f}"
    return str(v)


def tex_escape(s):
    return str(s).replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")


def write_latex(path, rows, columns, caption, label):
    """columns: list of (key, header)."""
    cols = "l" * 2 + "r" * (len(columns) - 2)
    lines = ["\\begin{table}[t]", "\\centering", "\\small", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
             f"\\begin{{tabular}}{{{cols}}}", "\\toprule",
             " & ".join(h for _, h in columns) + " \\\\", "\\midrule"]
    prev = None
    for r in rows:
        if prev is not None and r["model"] != prev:
            lines.append("\\midrule")
        prev = r["model"]
        cells = []
        for k, _ in columns:
            if k == "model":
                cells.append(tex_escape(MODEL_LABEL.get(r["model"], r["model"])))
            elif k == "prompt":
                cells.append(tex_escape(PROMPT_NAME.get(r["prompt"], r["prompt"])))
            elif k in ("role", "run_type"):
                cells.append(tex_escape(r[k]))
            else:
                cells.append(fmt(k, r.get(k)))
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def group(rows, keys):
    d = collections.defaultdict(list)
    for r in rows:
        d[tuple(r[k] for k in keys)].append(r)
    return d


def table(rows, keys, extra=None):
    out = []
    for k, rs in group(rows, keys).items():
        row = dict(zip(keys, k))
        row.update(metrics(rs))
        if extra:
            row.update(extra(row, rs))
        out.append(row)
    return sorted(out, key=sort_key)


def main():
    ap = argparse.ArgumentParser(description="Make the paper's tables and charts from the graded answers.")
    ap.add_argument("--grading-dir", default="grading")
    ap.add_argument("--out-dir", default="results_tables")
    args = ap.parse_args()

    calls_path = os.path.join(args.grading_dir, "graded_calls.csv")
    if not os.path.exists(calls_path):
        sys.exit(f"Cannot find {calls_path}. Run grade_runs.py first.")
    rows = load_calls_csv(calls_path)
    stab = {}
    sp = os.path.join(args.grading_dir, "stability_summary.csv")
    if os.path.exists(sp):
        for r in read_csv(sp):
            stab[(r["model"], r["prompt"], r["condition"])] = float(r["mean_jaccard"])
    os.makedirs(args.out_dir, exist_ok=True)
    figdir = os.path.join(args.out_dir, "figures")
    os.makedirs(figdir, exist_ok=True)

    complete = [r for r in rows if r["condition"] == "complete"]
    incomplete = [r for r in rows if r["condition"] == "incomplete"]
    t0 = [r for r in complete if r["run_type"] == "t0"]
    t07 = [r for r in complete if r["run_type"] == "t07"]

    def add_stab(row, rs):
        return {"mean_jaccard": stab.get((row["model"], row["prompt"], "complete"), "")}

    t1 = table(t0, ["model", "prompt"])
    t2 = table(t07, ["model", "prompt"], add_stab)
    t3 = table(t0, ["model", "prompt", "role"])
    t4 = table(incomplete, ["model", "prompt", "run_type"])
    t6 = table([r for r in t0 if r["valid"]], ["model", "prompt"])

    # prompt (c) choices, from the graded citations
    t5 = []
    cp = os.path.join(args.grading_dir, "graded_citations.csv")
    if os.path.exists(cp):
        cc = [r for r in read_csv(cp) if r["prompt"] == "c" and r["condition"] == "complete"]
        for (model, rt), rs in sorted(group(cc, ["model", "run_type"]).items(), key=lambda kv: sort_key({"model": kv[0][0]})):
            cnt = collections.Counter((r["shortlist_type"], r["label"]) for r in rs)
            t5.append({"model": model, "prompt": "c", "run_type": rt, "selected": len(rs),
                       "selected_true_answers": sum(v for (st, lb), v in cnt.items() if st == "true"),
                       "selected_same_family_decoys": sum(v for (st, lb), v in cnt.items() if st == "same_family_other_version"),
                       "selected_other_product_decoys": sum(v for (st, lb), v in cnt.items() if st == "other_product"),
                       "cited_outside_list": sum(v for (st, lb), v in cnt.items() if st == "outside_list")})

    full_cols = ["model", "prompt"] + METRIC_FIELDS
    write_csv(os.path.join(args.out_dir, "table1_overall_t0.csv"), full_cols, t1)
    write_csv(os.path.join(args.out_dir, "table2_overall_t07.csv"), full_cols + ["mean_jaccard"], t2)
    write_csv(os.path.join(args.out_dir, "table3_by_role_t0.csv"), ["model", "prompt", "role"] + METRIC_FIELDS, t3)
    write_csv(os.path.join(args.out_dir, "table4_incomplete_input.csv"), ["model", "prompt", "run_type"] + METRIC_FIELDS, t4)
    if t5:
        write_csv(os.path.join(args.out_dir, "table5_prompt_c_choices.csv"),
                  ["model", "prompt", "run_type", "selected", "selected_true_answers", "selected_same_family_decoys",
                   "selected_other_product_decoys", "cited_outside_list"], t5)
    write_csv(os.path.join(args.out_dir, "table6_sensitivity_valid_only.csv"), full_cols, t6)

    main_cols = [("model", "Model"), ("prompt", "Prompt"), ("avg_cited_per_answer", "Cited/ans"), ("precision", "Prec."),
                 ("recall", "Rec."), ("fabricated_rate", "Fabr."), ("real_but_wrong_rate", "Wrong"),
                 ("abstention_rate", "Abst.")]
    write_latex(os.path.join(args.out_dir, "table1_overall_t0.tex"), t1, main_cols,
                "Temperature-0 run on the 15 services with a known version. Cited/ans: average number of CVEs per answer. "
                "Fabr.: share of cited CVEs that do not exist; Wrong: share that exist but do not apply. "
                "Neutral citations are excluded.", "tab:overall-t0")
    write_latex(os.path.join(args.out_dir, "table2_overall_t07.tex"), t2, main_cols + [("mean_jaccard", "Stab.")],
                "Three runs at temperature 0.7, pooled. Stab.: mean pairwise Jaccard similarity of the CVE sets.", "tab:overall-t07")
    write_latex(os.path.join(args.out_dir, "table3_by_role_t0.tex"), t3,
                [("model", "Model"), ("prompt", "Prompt"), ("role", "Role"), ("precision", "Prec."), ("recall", "Rec."),
                 ("fabricated_rate", "Fabr."), ("real_but_wrong_rate", "Wrong"), ("clean_service_ok_rate", "Clean ok")],
                "Temperature-0 run by version role. Clean ok: share of answers on a service with no applicable CVEs "
                "that correctly cite nothing.", "tab:by-role")
    write_latex(os.path.join(args.out_dir, "table4_incomplete_input.tex"), t4,
                [("model", "Model"), ("prompt", "Prompt"), ("run_type", "Runs"), ("abstention_rate", "Abst."),
                 ("answers_with_citation_rate", "Cites"), ("fabricated", "Fabr. n"), ("real_unsupported", "Unsupp. n")],
                "Services scanned without a version. Abst.: answers that say not sure. Cites: answers that cite at least one CVE.",
                "tab:incomplete")

    # ---- charts
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed: tables written, charts skipped (pip install matplotlib).")
        plt = None
    if plt is not None:
        plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})
        models = [m for m in MODEL_ORDER if any(r["model"] == m for r in t1)]
        llms = [m for m in models if not m.startswith("baseline")]
        colors = {"a": "#4C72B0", "b": "#DD8452", "c": "#55A868"}
        hatches = {"a": "", "b": "//", "c": ".."}

        def bars(ax, data, key, title, ylabel, models_):
            w = 0.25
            for j, p in enumerate(["a", "b", "c"]):
                vals = []
                for m in models_:
                    r = next((x for x in data if x["model"] == m and x["prompt"] == p), None)
                    v = r.get(key) if r else None
                    vals.append(100 * v if v not in (None, "") else 0)
                ax.bar([i + (j - 1) * w for i in range(len(models_))], vals, w, label=PROMPT_NAME[p], color=colors[p],
                       hatch=hatches[p], edgecolor="white")
            ax.set_xticks(range(len(models_)))
            ax.set_xticklabels(models_)
            ax.set_ylabel(ylabel)
            ax.set_title(title)
            ax.set_ylim(0, 100)

        def legend_below(fig, ax):
            handles, labels = ax.get_legend_handles_labels()
            fig.tight_layout(rect=[0, 0.1, 1, 1])
            fig.legend(handles, labels, loc="lower center", ncol=3, frameon=False, fontsize=7)

        fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.8), sharey=True)
        bars(axes[0], t1, "fabricated_rate", "Fabricated CVEs", "% of cited CVEs", llms)
        bars(axes[1], t1, "real_but_wrong_rate", "Real but wrong CVEs", "", llms)
        legend_below(fig, axes[0])
        fig.savefig(os.path.join(figdir, "fig1_hallucination_rates.png"), dpi=200)
        fig.savefig(os.path.join(figdir, "fig1_hallucination_rates.pdf"))
        plt.close(fig)

        latest = [r for r in t3 if r["role"] == "latest"]
        fig, ax = plt.subplots(figsize=(3.4, 2.6))
        bars(ax, latest, "clean_service_ok_rate", "Services with no applicable CVE", "% of answers that cite nothing", models)
        ax.tick_params(axis="x", labelrotation=20)
        legend_below(fig, ax)
        fig.savefig(os.path.join(figdir, "fig2_clean_services.png"), dpi=200)
        fig.savefig(os.path.join(figdir, "fig2_clean_services.pdf"))
        plt.close(fig)

        pooled = table(incomplete, ["model", "prompt"])
        if pooled:
            fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.6), sharey=True)
            bars(axes[0], pooled, "abstention_rate", "Says not sure", "% of answers", llms)
            bars(axes[1], pooled, "answers_with_citation_rate", "Cites at least one CVE", "", llms)
            for ax in axes:
                ax.set_xlabel("input without a version (prompts a and b)")
            legend_below(fig, axes[0])
            fig.savefig(os.path.join(figdir, "fig3_incomplete_input.png"), dpi=200)
            fig.savefig(os.path.join(figdir, "fig3_incomplete_input.pdf"))
            plt.close(fig)

    print(f"Tables and figures written to {args.out_dir}/")
    print("\nTemperature-0 overall (complete condition):")
    print(f"{'model':<24}{'p':<3}{'prec':>6}{'rec':>6}{'fabr%':>7}{'wrong%':>8}{'abst%':>7}")
    for r in t1:
        def p(x):
            return "-" if x == "" else f"{100 * x:.0f}"

        def f2(x):
            return "-" if x == "" else f"{x:.2f}"
        print(f"{r['model']:<24}{r['prompt']:<3}{f2(r['precision']):>6}{f2(r['recall']):>6}{p(r['fabricated_rate']):>7}"
              f"{p(r['real_but_wrong_rate']):>8}{p(r['abstention_rate']):>7}")


if __name__ == "__main__":
    main()
