#!/usr/bin/env python3
"""
check_paper_numbers.py - compare the numbers in the paper draft with the numbers recomputed from the graded data.

Run after grade_runs.py and make_results.py, from the nmap-lab folder:
    python grade_runs.py --runs-dir llm_runs baseline
    python make_results.py
    python check_paper_numbers.py

For each claim it prints what the paper says, what the data says, and OK or CHECK. It also writes
results_tables/paper_check.csv. A CHECK is not always an error in the paper: read the note, and either correct the
paper or tell the team why the grading differs. The paper values below were copied from the draft of 2026-11-12
(Nmap_CVE_Hallucination_IEEE_2.docx); edit them here if the draft changes.

It also reports the manual-review result ([N] and [X] of the paper) from grading/manual_review_sample.csv once the
column my_check is filled in.
"""

import csv
import json
import os
import sys

from grade_runs import load_calls_csv, read_csv

# Table IV of the draft: (Cit., Prec., Rec., Fab., RBW, Abst., Clean); "-" = shown as a dash
PAPER_IV = {
    ("Llama 3.2", "(a)"): (508, 0, 0, 39, 61, 0, 0),
    ("Llama 3.2", "(b)"): (45, 0, 0, 44, 56, 0, 0),
    ("Llama 3.2", "(c)"): (111, 41, 9, 0, 59, 0, 0),
    ("Phi-4-mini", "(a)"): (43, 0, 0, 0, 100, 0, 100),
    ("Phi-4-mini", "(b)"): (0, "-", 0, "-", "-", 0, 100),
    ("Phi-4-mini", "(c)"): (12, 33, 1, 0, 67, 87, 75),
    ("Qwen3.5", "(a)"): (47, 0, 0, 17, 83, 47, 100),
    ("Qwen3.5", "(b)"): (16, 0, 0, 25, 75, 0, 75),
    ("Qwen3.5", "(c)"): (80, 40, 7, 0, 60, 0, 0),
    ("Raw CPE", "-"): (288, 100, 59, 0, 0, "-", 100),
    ("Corrected CPE", "-"): (492, 100, 100, 0, 0, "-", 100),
}
IV_COLS = ["Cit.", "Prec.", "Rec.", "Fab.", "RBW", "Abst.", "Clean"]
PAPER_II = {  # version-specific NVD entries per service before neutral entries were removed
    "apache_old": 88, "apache_mid": 72, "apache_latest": 0, "nginx_old": 6, "nginx_mid": 2, "nginx_latest": 0,
    "mysql_old": 81, "mysql_mid": 118, "mysql_latest": 0, "redis_old": 29, "redis_mid": 21, "redis_latest": 0,
    "openssh_old": 34, "openssh_mid": 28, "openssh_latest": 20,
}
PAPER_STABILITY = {("llama3.2:3b", "a"): 0.05, ("llama3.2:3b", "b"): 0.03, ("llama3.2:3b", "c"): 0.72, ("qwen3.5:4b", "c"): 0.49}
LLMS = ["llama3.2:3b", "phi4-mini", "qwen3.5:4b"]

results = []


def check(section, claim, paper, data, ok=None, note=""):
    if ok is None:
        ok = str(paper) == str(data)
    results.append({"where": section, "claim": claim, "paper": paper, "data": data, "status": "OK" if ok else "CHECK", "note": note})


def sel(rows, **kw):
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items())]


def main():
    gdir, rdir = "grading", "results_tables"
    for p in (os.path.join(gdir, "graded_calls.csv"), os.path.join(rdir, "paper_table_iv.csv")):
        if not os.path.exists(p):
            sys.exit(f"Cannot find {p}. Run grade_runs.py and make_results.py first.")
    calls = load_calls_csv(os.path.join(gdir, "graded_calls.csv"))
    cits = read_csv(os.path.join(gdir, "graded_citations.csv"))
    llm = [r for r in calls if r["model"] in LLMS]

    # ---- Table IV
    for row in read_csv(os.path.join(rdir, "paper_table_iv.csv")):
        key = (row["Model"], row["Prompt"])
        if key not in PAPER_IV:
            continue
        for col, pv in zip(IV_COLS, PAPER_IV[key]):
            check("Table IV", f"{key[0]} {key[1]} {col}", pv, row[col])

    # ---- Section III, IV text
    check("III.D", "answers in the model run", 612, len(llm))
    if os.path.exists(os.path.join("llm_runs", "errors.jsonl")):
        n_err = sum(1 for _ in open(os.path.join("llm_runs", "errors.jsonl"), encoding="utf-8"))
        check("III.D", "calls with errors", 0, n_err)
    t07_ab = [r for r in llm if r["condition"] == "complete" and r["run_type"] == "t07" and r["prompt"] in ("a", "b")]
    check("IV.A", "citations under prompts (a),(b) at temperature 0.7", 574, sum(r["n_cited"] for r in t07_ab))
    check("IV.A", "of which correct", 2, sum(r["n_correct"] for r in t07_ab))
    t0_ab_correct = sum(r["n_correct"] for r in llm if r["condition"] == "complete" and r["run_type"] == "t0" and r["prompt"] in ("a", "b"))
    check("Abstract / IV.A", "correct citations under (a),(b) at temperature 0", 0, t0_ab_correct)
    if sum(r["n_correct"] for r in t07_ab):
        check("Abstract / Conclusion", "'no correct CVE ... unless a candidate list was supplied' (all runs)", "none",
              f"{sum(r['n_correct'] for r in t07_ab)} correct at temperature 0.7 under (a),(b)", ok=False,
              note="true at temperature 0 only; say 'at temperature 0' or 'almost none'")

    la = sel(llm, model="llama3.2:3b", prompt="a", run_type="t0", condition="complete")
    check("IV.A", "Llama (a) answers cut off at the output limit", 10, sum(1 for r in la if r["truncated"]))
    valid_la = [r for r in la if r["valid"]]
    check("IV.A", "Llama (a) valid answers", 5, len(valid_la))
    check("IV.A", "Llama (a) citations in the valid answers", 19, sum(r["n_cited"] for r in valid_la))
    check("IV.A", "fabricated or rejected among them", 5, sum(r["n_fabricated"] + r["n_rejected"] for r in valid_la))
    lb = [r for r in llm if r["model"] == "llama3.2:3b" and r["prompt"] == "b" and r["condition"] == "complete"]
    check("IV.A", "Llama (b): answers with the not-sure flag (all runs)", 0, sum(1 for r in lb if r["not_sure"]))
    pb0 = sel(llm, model="phi4-mini", prompt="b", run_type="t0", condition="complete")
    pb7 = sel(llm, model="phi4-mini", prompt="b", run_type="t07", condition="complete")
    check("IV.A", "Phi (b) at temperature 0: citations / not-sure flags", "0 / 0",
          f"{sum(r['n_cited'] for r in pb0)} / {sum(1 for r in pb0 if r['not_sure'])}")
    n7 = sum(1 for r in pb7 if r["not_sure"])
    check("IV.A", "Phi (b) 'without ever setting the not-sure flag' (also at temperature 0.7)", "never", f"{n7} of {len(pb7)} answers at 0.7",
          ok=(n7 == 0), note="if it is not zero, limit the sentence to temperature 0")

    # ---- prompt (c)
    c_cits = [c for c in cits if c["prompt"] == "c" and c["condition"] == "complete" and c["model"] in LLMS]
    check("IV.B", "citations outside the candidate list", 0, sum(1 for c in c_cits if c["shortlist_type"] == "outside_list"))
    c0 = [c for c in c_cits if c["run_type"] == "t0"]
    ll = [c for c in c0 if c["model"] == "llama3.2:3b"]
    check("IV.B", "Llama (c): real CVEs selected", 45, sum(1 for c in ll if c["label"] == "correct"))
    check("IV.B", "Llama (c): decoys selected", 66, sum(1 for c in ll if c["label"] == "real_but_wrong"))
    check("IV.B", "Llama (c): decoys of the same product, other versions", 40,
          sum(1 for c in ll if c["label"] == "real_but_wrong" and c["shortlist_type"] == "same_family_other_version"))
    qq = [c for c in c0 if c["model"] == "qwen3.5:4b"]
    check("IV.B", "Qwen (c): real CVEs selected", 32, sum(1 for c in qq if c["label"] == "correct"))
    check("IV.B", "Qwen (c): decoys selected", 48, sum(1 for c in qq if c["label"] == "real_but_wrong"))
    pc = sel(llm, model="phi4-mini", prompt="c", run_type="t0", condition="complete")
    check("IV.B", "Phi (c): answers that cite something", 3, sum(1 for r in pc if r["n_cited"] > 0))
    check("IV.B", "Phi (c): answers with the not-sure flag", 13, sum(1 for r in pc if r["not_sure"]))
    iv = {(r["Model"], r["Prompt"]): r for r in read_csv(os.path.join(rdir, "paper_table_iv.csv"))}
    precs = [int(iv[(m, "(c)")]["Prec."]) for m in ("Llama 3.2", "Phi-4-mini", "Qwen3.5") if (m, "(c)") in iv and iv[(m, "(c)")]["Prec."] != "-"]
    recs = [int(iv[(m, "(c)")]["Rec."]) for m in ("Llama 3.2", "Phi-4-mini", "Qwen3.5") if (m, "(c)") in iv and iv[(m, "(c)")]["Rec."] != "-"]
    if precs:
        check("IV.B", "precision with the candidate list: min to max (%)", "33 to 41", f"{min(precs)} to {max(precs)}")
        check("IV.B", "recall with the candidate list stays below (%)", "<10", f"max {max(recs)}", ok=max(recs) < 10)
    raw_crit = sel(calls, model="baseline_raw_cpe", condition="complete")
    ct = sum(r["critical_truth_size"] or 0 for r in raw_crit)
    cc = sum(r["correct_critical"] or 0 for r in raw_crit)
    if ct:
        check("IV.B", "raw CPE baseline: recall for critical CVEs (%)", 97, int(100 * cc / ct + 0.5))

    # ---- incomplete input
    inc0 = [r for r in llm if r["condition"] == "incomplete" and r["run_type"] == "t0"]
    ia = sel(inc0, model="llama3.2:3b", prompt="a")
    check("IV.C", "Llama (a), no version: identifiers listed", 113, sum(r["n_cited"] for r in ia))
    check("IV.C", "of which fabricated or rejected", 35, sum(r["n_fabricated"] + r["n_rejected"] for r in ia))
    for m, p in [("phi4-mini", "a"), ("phi4-mini", "b"), ("qwen3.5:4b", "a"), ("qwen3.5:4b", "b"), ("llama3.2:3b", "b")]:
        rs = sel(inc0, model=m, prompt=p)
        check("IV.C", f"{m} ({p}), no version: answers with the flag at temperature 0 (of {len(rs)})", len(rs), sum(1 for r in rs if r["not_sure"]))

    # ---- stability and times
    sp = os.path.join(gdir, "stability_summary.csv")
    if os.path.exists(sp):
        stab = {(r["model"], r["prompt"]): r["mean_jaccard"] for r in read_csv(sp) if r["condition"] == "complete"}
        for (m, p), v in PAPER_STABILITY.items():
            d = stab.get((m, p))
            check("IV.D", f"stability {m} ({p})", f"{v:.2f}", "n/a" if d is None else f"{float(d):.2f}")
    times = {}
    for m in LLMS:
        for p in ("a", "b", "c"):
            xs = [r["wall_seconds"] for r in llm if r["model"] == m and r["prompt"] == p and r["condition"] == "complete" and r["wall_seconds"] is not None]
            if xs:
                times[(m, p)] = sum(xs) / len(xs)
    for m, lo, hi in [("llama3.2:3b", 2, 6), ("phi4-mini", 2, 6), ("qwen3.5:4b", 6, 19)]:
        vals = [v for (mm, _), v in times.items() if mm == m]
        if vals:
            check("IV.D", f"average seconds per answer, {m} (paper: {lo} to {hi})", f"{lo} to {hi}",
                  f"{min(vals):.1f} to {max(vals):.1f}", ok=(min(vals) >= lo - 0.5 and max(vals) <= hi + 0.5),
                  note="averages over all complete-condition runs; edit the range in the text if it does not fit")

    # ---- lab and ground truth
    sp2 = os.path.join("ground_truth", "nvd_truth_summary.csv")
    if os.path.exists(sp2):
        for r in read_csv(sp2):
            if r["service_id"] in PAPER_II:
                check("Table II", f"{r['service_id']} version-specific NVD entries", PAPER_II[r["service_id"]], r.get("n_truth_version_specific", "?"))
        others = [r for r in read_csv(sp2) if not r["service_id"].startswith("openssh")]
        diff = sum(int(r.get("n_only_virtualmatch") or 0) + int(r.get("n_only_cpename") or 0) for r in others)
        check("III.B", "services other than OpenSSH where the two query methods differ", 0, diff)
    tp = os.path.join("ground_truth", "nvd_truth.csv")
    if os.path.exists(tp):
        fam = collections_counter = {}
        for r in read_csv(tp):
            if r.get("unbounded_version_match") == "True" or "disputed" in (r.get("cve_tags") or ""):
                fam.setdefault(r["product_family"], set()).add(r["cve_id"])
        check("III.B", "neutral (all-versions or disputed) entries: OpenSSH / Redis / total", "5 / 1 / 6",
              f"{len(fam.get('OpenSSH', ()))} / {len(fam.get('Redis', ()))} / {sum(len(v) for v in fam.values())}")
    mp = os.path.join("llm_runs", "run_meta.json")
    if os.path.exists(mp):
        meta = json.load(open(mp, encoding="utf-8"))
        gpu = {k: v.get("gpu_percent") for k, v in meta.get("gpu_fit", {}).items()}
        check("Table III", "share on GPU: Llama / Phi / Qwen (%)", "80 / 64 / 48",
              " / ".join(str(gpu.get(m)) for m in LLMS))
        check("Table III", "Ollama version", "0.33.3", meta.get("ollama_version"))

    # ---- manual review
    rp = os.path.join(gdir, "manual_review_sample.csv")
    if os.path.exists(rp):
        rows = read_csv(rp)
        filled = [r for r in rows if (r.get("my_check") or "").strip()]
        yes = sum(1 for r in filled if r["my_check"].strip().lower() == "yes")
        no = sum(1 for r in filled if r["my_check"].strip().lower() == "no")
        unsure = sum(1 for r in filled if r["my_check"].strip().lower() == "unsure")
        if filled:
            agree = f"{100 * yes / (yes + no):.0f}" if (yes + no) else "n/a"
            check("III.B [N],[X]", "manual check: N citations / X% agreement (yes of yes+no)", "[N] / [X]%",
                  f"N = {len(filled)} (yes {yes}, no {no}, unsure {unsure}) / X = {agree}%", ok=False,
                  note="fill [N] and [X] in the paper; the sample takes the same number of citations per label")
        else:
            check("III.B [N],[X]", "manual check", "[N] / [X]%", "my_check is still empty", ok=False)

    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "paper_check.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["where", "claim", "paper", "data", "status", "note"])
        w.writeheader()
        w.writerows(results)
    bad = [r for r in results if r["status"] != "OK"]
    print(f"{len(results)} claims compared: {len(results) - len(bad)} OK, {len(bad)} to check\n")
    for r in bad:
        print(f"CHECK  [{r['where']}] {r['claim']}\n       paper: {r['paper']}    data: {r['data']}" + (f"\n       note: {r['note']}" if r["note"] else ""))
    print(f"\nFull list: {os.path.join(rdir, 'paper_check.csv')}")


if __name__ == "__main__":
    main()
