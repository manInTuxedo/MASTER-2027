import argparse
import csv
import json
import os
import random

ap = argparse.ArgumentParser()
ap.add_argument("--per-label", type=int, default=8)
ap.add_argument("--seed", type=int, default=7)
ap.add_argument("--grading-dir", default="grading")
ap.add_argument("--nmap-json", default=os.path.join("results", "nmap_results.json"))
args = ap.parse_args()

with open(os.path.join(args.grading_dir, "graded_citations.csv"), newline="", encoding="utf-8-sig") as f:
    rows = [r for r in csv.DictReader(f) if r["condition"] == "complete" and not r["model"].startswith("baseline")]
version, product = {}, {}
if os.path.exists(args.nmap_json):
    with open(args.nmap_json, encoding="utf-8") as f:
        for r in json.load(f)["records"]:
            version[r["id"]] = r.get("detected_version")
            product[r["id"]] = r.get("product")

rng = random.Random(args.seed)
sample = []
for label in sorted({r["label"] for r in rows}):
    pool = sorted({(r["service_id"], r["cve_id"]): r for r in rows if r["label"] == label}.values(),
                  key=lambda r: (r["service_id"], r["cve_id"]))
    sample += rng.sample(pool, min(args.per_label, len(pool)))
out = os.path.join(args.grading_dir, "manual_review_sample.csv")
fields = ["label", "service_id", "product", "detected_version", "cve_id", "nvd_page", "model", "prompt", "my_check"]
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in sample:
        w.writerow({"label": r["label"], "service_id": r["service_id"], "product": product.get(r["service_id"], ""),
                    "detected_version": version.get(r["service_id"], ""), "cve_id": r["cve_id"],
                    "nvd_page": f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}", "model": r["model"],
                    "prompt": r["prompt"], "my_check": ""})
print(f"Wrote {len(sample)} citations to {out}")