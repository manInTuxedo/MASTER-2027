#!/usr/bin/env python3
"""
summarize_runs.py - quick summary of what run_models.py has saved so far.

    python summarize_runs.py llm_pilot --estimate     check the pilot and estimate the full run time
    python summarize_runs.py llm_runs                 progress and health of the full run

For every model / prompt / condition it shows how many calls are saved, how many answers parsed as valid
JSON, how many were cut off by the length limit, the average seconds and tokens per second, the average
number of CVEs cited, and how often the model answered "not sure". It also shows whether each model
fitted on the GPU. Nothing here is graded; it is only a health check.

--estimate guesses the total time of the full plan (3 models x 3 prompts x 15 services x 4 runs, plus the
incomplete-input condition: 3 services x prompts a and b) from the averages found in the folder.
"""

import argparse
import collections
import json
import os
import sys

FULL_PLAN_PER_MODEL = {"a": 15 * 4 + 3 * 4, "b": 15 * 4 + 3 * 4, "c": 15 * 4}  # calls per model and prompt


def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def fmt(x, nd=1):
    return "-" if x is None else f"{x:.{nd}f}"


def main():
    ap = argparse.ArgumentParser(description="Summarize the output of run_models.py.")
    ap.add_argument("folder", nargs="?", default="llm_runs")
    ap.add_argument("--estimate", action="store_true", help="estimate the time of the full 612-call plan")
    args = ap.parse_args()

    raw_path = os.path.join(args.folder, "raw_calls.jsonl")
    if not os.path.exists(raw_path):
        sys.exit(f"Cannot find {raw_path}")
    recs = []
    with open(raw_path, encoding="utf-8") as f:
        for line in f:
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    err_path = os.path.join(args.folder, "errors.jsonl")
    n_err = sum(1 for _ in open(err_path, encoding="utf-8")) if os.path.exists(err_path) else 0
    meta = {}
    meta_path = os.path.join(args.folder, "run_meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

    print(f"Folder: {args.folder}   saved calls: {len(recs)}   failed calls (errors.jsonl): {n_err}")
    if meta:
        print(f"Ollama {meta.get('ollama_version')}   protocol {meta.get('protocol_version')}   sessions: {len(meta.get('sessions', []))}")
        for m, info in meta.get("models", {}).items():
            gpu = meta.get("gpu_fit", {}).get(m, {}).get("gpu_percent")
            print(f"  {m:<14} digest {str(info.get('digest'))[:12]:<12}  on GPU: {('%d%%' % gpu) if gpu is not None else 'unknown'}")

    groups = collections.defaultdict(list)
    for r in recs:
        groups[(r["model"], r["condition"], r["prompt"])].append(r)

    print(f"\n{'model':<14} {'condition':<10} {'p':<2} {'calls':>5} {'valid':>6} {'cut':>4} {'sec':>6} {'tok/s':>6} {'CVEs':>5} {'not_sure':>8}")
    averages = {}
    for (model, cond, pid), rs in sorted(groups.items()):
        valid = sum(1 for r in rs if r.get("parse_error") is None)
        cut = sum(1 for r in rs if r.get("done_reason") == "length")
        secs = avg([r.get("wall_seconds") for r in rs])
        toks = avg([(r["eval_count"] / (r["eval_duration_ns"] / 1e9)) if r.get("eval_count") and r.get("eval_duration_ns") else None for r in rs])
        cves = avg([len(r["parsed"]["cves"]) for r in rs if r.get("parsed") and isinstance(r["parsed"].get("cves"), list)])
        ns = sum(1 for r in rs if r.get("parsed") and r["parsed"].get("not_sure") is True)
        print(f"{model:<14} {cond:<10} {pid:<2} {len(rs):>5} {valid:>6} {cut:>4} {fmt(secs):>6} {fmt(toks):>6} {fmt(cves):>5} {ns:>8}")
        if cond == "complete":
            averages[(model, pid)] = secs

    bad = [r for r in recs if r.get("parse_error")]
    if bad:
        print(f"\n{len(bad)} answers had a parse problem. First few:")
        for r in bad[:5]:
            print(f"  {r['call_id']}: {r['parse_error']}")

    if args.estimate:
        total, missing = 0.0, []
        models = sorted({m for m, _ in averages})
        for m in models:
            for pid, n in FULL_PLAN_PER_MODEL.items():
                a = averages.get((m, pid))
                if a is None:
                    missing.append(f"{m}/{pid}")
                else:
                    total += a * n
        print(f"\nEstimated time for the full plan with these averages: about {total / 60:.0f} minutes ({total / 3600:.1f} hours)")
        print("It is a rough guess from a few calls; the temperature 0.7 runs can differ a little.")
        if missing:
            print("Not included (no data yet): " + ", ".join(missing))


if __name__ == "__main__":
    main()
