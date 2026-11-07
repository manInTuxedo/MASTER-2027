#!/usr/bin/env python3
"""
make_shortlists.py - build the candidate CVE shortlists used by prompt (c).

Prompt (c) gives the model a list of candidate CVEs and asks it to select only the ones that apply.
For every service this script builds one fixed list (the same list for every model and every run):

  * up to N_TRUE real answers for that service (chosen at random, with a fixed seed, from the CVEs
    that NVD attaches to this exact version; unambiguous entries only: not "all versions" entries
    and not entries tagged disputed),
  * the rest are decoys that do NOT apply to the service:
      - about half are real CVEs of the same product family that apply to other versions
        ("same_family_other_version"), which test the "real but wrong" case,
      - the rest are real CVEs of other products ("other_product").
  * services with no applicable CVEs (for example the latest versions) get a list of decoys only,
    so the correct answer is to select nothing.

The list is shuffled with the same seed. The model sees only the CVE id and the first sentence of its
NVD description; the flags is_true and decoy_type stay in the file for the grader.

Inputs : ground_truth/nvd_truth.csv, ground_truth/nvd_truth_summary.csv, ground_truth/nvd_raw/
Outputs: prompts/shortlists.json   (used by run_models.py)
         prompts/shortlists_preview.csv   (the same lists in a table anyone can read)

Run from the nmap-lab folder:
    python make_shortlists.py
"""

import argparse
import csv
import datetime as dt
import glob
import hashlib
import json
import os
import random
import re
import sys


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def load_descriptions(raw_dir):
    """cve id -> English description, taken from the raw NVD replies saved by build_nvd_truth.py."""
    desc = {}
    for p in glob.glob(os.path.join(raw_dir, "*.json")):
        try:
            with open(p, encoding="utf-8") as f:
                rec = json.load(f)
        except (OSError, ValueError):
            continue
        for v in ((rec.get("body") or {}).get("vulnerabilities") or []):
            cve = v.get("cve", {})
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en" and cve.get("id"):
                    desc.setdefault(cve["id"], d.get("value", ""))
                    break
    return desc


def first_sentence(text, limit=240):
    text = " ".join((text or "").split())
    if not text:
        return "(no description available)"
    m = re.search(r"(?<=[.!?])\s", text)
    first = text[: m.start()] if m else text
    if len(first) > limit:
        first = first[: limit - 3].rstrip() + "..."
    return first


def main():
    ap = argparse.ArgumentParser(description="Build the fixed candidate shortlists for prompt (c).")
    ap.add_argument("--truth", default=os.path.join("ground_truth", "nvd_truth.csv"))
    ap.add_argument("--summary", default=os.path.join("ground_truth", "nvd_truth_summary.csv"))
    ap.add_argument("--raw-dir", default=os.path.join("ground_truth", "nvd_raw"))
    ap.add_argument("--out", default=os.path.join("prompts", "shortlists.json"))
    ap.add_argument("--size", type=int, default=10, help="candidates per list")
    ap.add_argument("--n-true", type=int, default=5, help="maximum real answers per list")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    for p in (args.truth, args.summary):
        if not os.path.exists(p):
            sys.exit(f"Cannot find {p}. Run build_nvd_truth.py first, from the nmap-lab folder.")

    truth_rows = read_csv(args.truth)
    summary_rows = read_csv(args.summary)
    have_flags = bool(truth_rows) and "unbounded_version_match" in truth_rows[0]
    if not have_flags:
        print("[warning] nvd_truth.csv has no unbounded_version_match column (older build_nvd_truth.py): "
              "all truth CVEs are treated as unambiguous. Re-run build_nvd_truth.py (it uses its cache).")

    family = {r["service_id"]: r["product_family"] for r in summary_rows}
    all_ids = {sid: set() for sid in family}
    clear_ids = {sid: set() for sid in family}  # unambiguous entries only
    for r in truth_rows:
        sid = r["service_id"]
        if sid not in family:
            continue
        all_ids[sid].add(r["cve_id"])
        ambiguous = have_flags and (r.get("unbounded_version_match") == "True" or "disputed" in (r.get("cve_tags") or ""))
        if not ambiguous:
            clear_ids[sid].add(r["cve_id"])

    descriptions = load_descriptions(args.raw_dir)
    if not descriptions:
        print(f"[warning] no descriptions found in {args.raw_dir}; the lists will show ids only.")

    shortlists, preview = {}, []
    for sid in sorted(family):
        rng = random.Random(f"{args.seed}:{sid}")
        fam = family[sid]
        n_true = min(args.n_true, len(clear_ids[sid]))
        true_ids = rng.sample(sorted(clear_ids[sid]), n_true)

        same_pool = set()
        other_pool = set()
        for other, ids in all_ids.items():
            if other == sid:
                continue
            (same_pool if family[other] == fam else other_pool).update(ids)
        forbidden = all_ids[sid] | set(true_ids)
        same_pool = sorted(same_pool - forbidden)
        other_pool = sorted(other_pool - forbidden - set(same_pool))

        n_decoy = args.size - n_true
        want_same = min(len(same_pool), (n_decoy + 1) // 2)
        want_other = min(len(other_pool), n_decoy - want_same)
        if want_same + want_other < n_decoy:  # not enough other products: top up from the same family
            want_same = min(len(same_pool), n_decoy - want_other)
        same = rng.sample(same_pool, want_same)
        other = rng.sample(other_pool, want_other)

        items = (
            [{"cve_id": c, "is_true": True, "decoy_type": "true"} for c in true_ids]
            + [{"cve_id": c, "is_true": False, "decoy_type": "same_family_other_version"} for c in same]
            + [{"cve_id": c, "is_true": False, "decoy_type": "other_product"} for c in other]
        )
        rng.shuffle(items)
        for it in items:
            it["description"] = first_sentence(descriptions.get(it["cve_id"]))
            preview.append({"service_id": sid, "cve_id": it["cve_id"], "is_true": it["is_true"],
                            "decoy_type": it["decoy_type"], "description": it["description"]})
        shortlists[sid] = {"service_id": sid, "product_family": fam, "items": items}
        print(f"{sid:<15} {n_true} true + {len(same)} same-family decoys + {len(other)} other-product decoys")

    with open(args.truth, "rb") as f:
        truth_sha = hashlib.sha256(f.read()).hexdigest()
    out = {
        "meta": {
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "seed": args.seed, "list_size": args.size, "max_true_per_list": args.n_true,
            "truth_file": args.truth, "truth_file_sha256": truth_sha,
            "rule": "true items: unambiguous NVD entries for this exact version (not all-versions, not disputed); "
                    "decoys: about half same family other version, rest other products; none applies to the service",
        },
        "shortlists": shortlists,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    preview_path = os.path.join(os.path.dirname(args.out) or ".", "shortlists_preview.csv")
    with open(preview_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["service_id", "cve_id", "is_true", "decoy_type", "description"])
        w.writeheader()
        w.writerows(preview)
    print(f"\nWrote {args.out} and {preview_path}")


if __name__ == "__main__":
    main()
