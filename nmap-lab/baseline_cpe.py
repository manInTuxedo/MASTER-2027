#!/usr/bin/env python3
"""
baseline_cpe.py - the non-AI baseline: look up each service's CPE in the NVD.

For every service in results/nmap_results.json it asks NVD which CVEs are attached to the CPE (the same cpeName +
isVulnerable query that build_nvd_truth.py uses) and saves the result as an "answer" in the same format as the models'
answers, in baseline/raw_calls.jsonl. grade_runs.py then grades it exactly like a model:

    python baseline_cpe.py
    python grade_runs.py --runs-dir llm_runs baseline

Two baselines are produced:
  baseline_raw_cpe        the CPE exactly as Nmap printed it (what a simple script would do)
  baseline_corrected_cpe  the same lookup under the known NVD vendor aliases (f5:nginx, oracle:mysql, OpenSSH p1, ...)
                          This one finds everything the ground truth finds, so it is an upper bound, not a competitor.

The replies are read from ground_truth/nvd_raw/ (saved by build_nvd_truth.py), so no new request to NVD is needed
unless that folder is missing. Both baselines return only real NVD records, so they cannot fabricate a CVE.

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import datetime as dt
import json
import os
import sys

from build_nvd_truth import DEFAULT_BASE_URL, NvdClient, build_variants, fetch_all

MODELS = ("baseline_raw_cpe", "baseline_corrected_cpe")


def answer_record(model, svc, cves):
    obj = {"product": svc.get("product") or "", "version": svc.get("detected_version") or "",
           "not_sure": False, "cves": [{"cve_id": c, "confidence": "high"} for c in sorted(cves)]}
    text = json.dumps(obj)
    return {
        "call_id": f"{model}|-|{svc['id']}|t0", "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "protocol_version": "baseline", "condition": "complete", "model": model, "prompt": "-", "service_id": svc["id"],
        "run": "t0", "temperature": 0.0, "seed": None, "scan_result": svc.get("llm_input_text"),
        "response_text": text, "parsed": obj, "parse_error": None, "done_reason": "stop",
        "wall_seconds": None, "eval_count": None, "eval_duration_ns": None,
    }


def main():
    ap = argparse.ArgumentParser(description="Build the NVD CPE-lookup baselines.")
    ap.add_argument("--nmap-json", default=os.path.join("results", "nmap_results.json"))
    ap.add_argument("--cache-dir", default=os.path.join("ground_truth", "nvd_raw"))
    ap.add_argument("--out-dir", default="baseline")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--page-size", type=int, default=2000)
    args = ap.parse_args()

    if not os.path.exists(args.nmap_json):
        sys.exit(f"Cannot find {args.nmap_json}")
    with open(args.nmap_json, encoding="utf-8") as f:
        records = json.load(f)["records"]
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    client = NvdClient(args.base_url, api_key, args.cache_dir, 0.7 if api_key else 6.2, args.page_size, False)

    out = []
    print(f"{'service':<16}{'raw CPE':>9}{'corrected':>11}")
    for svc in records:
        cpe = svc.get("cpe23_primary")
        raw, corrected = set(), set()
        if cpe:
            r = fetch_all(client, "cpeName", cpe)
            raw = set(r["cves"]) if r["status"] == "ok" else set()
            for _, vcpe in build_variants(cpe):
                v = fetch_all(client, "cpeName", vcpe)
                if v["status"] == "ok":
                    corrected |= set(v["cves"])
        out.append(answer_record("baseline_raw_cpe", svc, raw))
        out.append(answer_record("baseline_corrected_cpe", svc, corrected))
        print(f"{svc['id']:<16}{len(raw):>9}{len(corrected):>11}")

    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, "raw_calls.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for rec in out:
            f.write(json.dumps(rec) + "\n")
    print(f"\nWrote {len(out)} baseline answers to {path}")
    print(f"Network requests: {client.network_requests}   cache hits: {client.cache_hits}")
    print("Next: python grade_runs.py --runs-dir llm_runs baseline")


if __name__ == "__main__":
    main()
