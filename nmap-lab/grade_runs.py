#!/usr/bin/env python3
"""
grade_runs.py - grade every CVE the models cited, following PROTOCOL.md (v1.1 grading rules).

Reads  : llm_runs/raw_calls.jsonl            answers saved by run_models.py
         baseline/raw_calls.jsonl            (optional) the non-AI baselines made by baseline_cpe.py, graded the same way
         ground_truth/nvd_truth.csv, nvd_truth_summary.csv, nvd_raw/    built by build_nvd_truth.py
         prompts/shortlists.json             candidate lists of prompt c
         NVD API (cveId lookups, only for cited CVEs that are not already in the truth table)
Writes : grading/graded_citations.csv   one row per cited CVE, with its label
         grading/graded_calls.csv       one row per answer (counts, missing CVEs, empty-answer outcome)
         grading/summary_by_condition.csv, summary_by_service.csv, stability.csv, stability_summary.csv
         grading/neutral_review.csv     every CVE treated as neutral, with its NVD description, for review
         grading/grading_meta.json      hashes, dates, settings, notes
         grading/nvd_cve_cache/         every NVD reply used (evidence, and a cache for re-runs)

CVE ids are pulled with a regular expression from the raw text of EVERY answer, including answers whose JSON is
broken or cut off. If an answer was cut off by the length limit, an id that touches the very end of the text
is ignored, because its last digits may be missing.

Labels, for each distinct cited CVE of an answer (checked in this order):
  fabricated       NVD has no record of it
  rejected         NVD records it as rejected
  neutral          not counted as correct or wrong, reported separately. Two kinds:
                     disputed_or_all_versions : NVD entries that apply to all versions or are tagged disputed (this
                                                includes the three OpenSSH entries named by the professor)
                     mysql_bundled_library    : for MySQL services, CVEs of a third-party library that MySQL bundles
                                                (zlib, OpenSSL, ...), recognised from the NVD record; see BUNDLED_* below
  correct          in the version-specific ground truth of the service
  real_unscored    exists, but NVD has no applicability analysis for it yet
  real_but_wrong   exists, analysed, but not in the ground truth of the service
Incomplete-input answers (no version in the scan line) have no ground truth: a cited CVE is fabricated, rejected, or
real_unsupported.

Missing CVEs: the ground-truth CVEs of the service that an answer does not cite (n_missing).
Empty-answer rule: an answer that cites nothing is "correct" on a clean service (empty ground truth) and misses every
ground-truth CVE on any other service. See answer_outcome in graded_calls.csv.

Run from the nmap-lab folder:
    python grade_runs.py                                         grade llm_runs
    python grade_runs.py --runs-dir llm_runs baseline            grade the models and the baselines together
Needs the NVD_API_KEY environment variable for speed (without it, about 6 s per CVE lookup).
This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import collections
import csv
import datetime as dt
import glob
import hashlib
import itertools
import json
import os
import re
import sys

from build_nvd_truth import DEFAULT_BASE_URL, NvdClient

PROFESSOR_NAMED = {"CVE-2007-2768", "CVE-2008-3844", "CVE-2023-51767"}  # OpenSSH entries named by the professor
NAMED_FAMILY = "OpenSSH"
MYSQL_FAMILY = "MySQL"
UNSCORED_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis", "Deferred"}
CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# MySQL bundled third-party libraries: a CVE whose NVD description names one of these words, or whose vulnerable
# CPE products include one of these vendor:product names, is neutral when cited for a MySQL service.
# Edit the lists if the professor wants a different set.
BUNDLED_WORDS = ["zlib", "openssl", "libxml2", "libxslt", "curl", "libcurl", "lz4", "zstd", "zstandard", "protobuf",
                 "libedit", "icu", "boost", "libevent", "rapidjson", "libcbor", "libfido2", "wolfssl", "yassl"]
BUNDLED_PRODUCTS = {"openssl:openssl", "zlib:zlib", "xmlsoft:libxml2", "xmlsoft:libxslt", "haxx:curl", "haxx:libcurl",
                    "lz4_project:lz4", "facebook:zstandard", "google:protobuf", "boost:boost", "wolfssl:wolfssl",
                    "yassl:yassl", "libevent_project:libevent"}
BUNDLED_RE = re.compile(r"\b(" + "|".join(re.escape(w) for w in BUNDLED_WORDS) + r")\b", re.I)

LABELS = ["correct", "real_but_wrong", "fabricated", "rejected", "neutral", "real_unscored", "real_unsupported"]
NEUTRAL_REASONS = ["disputed_or_all_versions", "mysql_bundled_library"]
INT_COLS = ["n_cited", "n_neutral_disputed", "n_neutral_bundled", "correct_critical", "n_missing", "truth_size",
            "critical_truth_size"] + [f"n_{l}" for l in LABELS]
BOOL_COLS = ["valid", "truncated", "not_sure", "empty_answer", "clean_service"]


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def ratio(a, b):
    return round(a / b, 4) if b else ""


def to_float(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def run_type(run):
    return "t0" if run == "t0" else "t07"


def role_of(service_id):
    for part in reversed(str(service_id).split("_")):
        if part in ("old", "mid", "latest"):
            return part
    return ""


def load_calls_csv(path):
    """Read graded_calls.csv back with proper types (used by make_results.py)."""
    rows = read_csv(path)
    for r in rows:
        for c in INT_COLS:
            r[c] = int(r[c]) if r.get(c, "") not in ("", None) else None
        for c in BOOL_COLS:
            r[c] = {"True": True, "False": False}.get(r.get(c), None)
        for c in ("wall_seconds", "tokens_per_second"):
            r[c] = to_float(r.get(c))
        r["role"] = role_of(r["service_id"])
    return rows


def metrics(rows):
    """All metrics of PROTOCOL.md for a list of graded answers (python-typed rows)."""
    n = len(rows)
    valid = [x for x in rows if x["valid"]]
    cit = sum(x["n_cited"] for x in rows)
    neutral = sum(x["n_neutral"] for x in rows)
    judged = cit - neutral
    c = sum(x["n_correct"] for x in rows)
    rec_rows = [x for x in rows if x["truth_size"]]
    crit_rows = [x for x in rows if x["critical_truth_size"]]
    clean_rows = [x for x in rows if x["clean_service"] is True]
    secs = [x["wall_seconds"] for x in rows if x["wall_seconds"] is not None]
    tps = [x["tokens_per_second"] for x in rows if x["tokens_per_second"] is not None]
    return {
        "calls": n, "valid_json_answers": len(valid), "invalid_output_rate": ratio(n - len(valid), n),
        "citations": cit, "avg_cited_per_answer": round(cit / n, 1) if n else "", "neutral_citations": neutral,
        "neutral_disputed": sum(x["n_neutral_disputed"] for x in rows),
        "neutral_mysql_bundled": sum(x["n_neutral_bundled"] for x in rows),
        "correct": c, "real_but_wrong": sum(x["n_real_but_wrong"] for x in rows),
        "fabricated": sum(x["n_fabricated"] for x in rows), "rejected": sum(x["n_rejected"] for x in rows),
        "real_unscored": sum(x["n_real_unscored"] for x in rows), "real_unsupported": sum(x["n_real_unsupported"] for x in rows),
        "fabricated_rate": ratio(sum(x["n_fabricated"] for x in rows), judged),
        "real_but_wrong_rate": ratio(sum(x["n_real_but_wrong"] for x in rows), judged),
        "precision": ratio(c, judged),
        "recall": ratio(sum(x["n_correct"] for x in rec_rows), sum(x["truth_size"] for x in rec_rows)),
        "recall_critical": ratio(sum(x["correct_critical"] for x in crit_rows), sum(x["critical_truth_size"] for x in crit_rows)),
        "missing_cves": sum(x["n_missing"] or 0 for x in rec_rows),
        "abstention_rate": ratio(sum(1 for x in rows if x["not_sure"]), n),
        "empty_answer_rate": ratio(sum(1 for x in rows if x["empty_answer"]), n),
        "clean_service_ok_rate": ratio(sum(1 for x in clean_rows if x["n_cited"] == 0), len(clean_rows)),
        "answers_with_citation_rate": ratio(sum(1 for x in rows if x["n_cited"] > 0), n),
        "avg_seconds": round(sum(secs) / len(secs), 2) if secs else "",
        "avg_tokens_per_second": round(sum(tps) / len(tps), 1) if tps else "",
    }


METRIC_FIELDS = ["calls", "valid_json_answers", "invalid_output_rate", "citations", "avg_cited_per_answer",
                 "neutral_citations", "neutral_disputed",
                 "neutral_mysql_bundled", "correct", "real_but_wrong", "fabricated", "rejected", "real_unscored",
                 "real_unsupported", "fabricated_rate", "real_but_wrong_rate", "precision", "recall", "recall_critical",
                 "missing_cves", "abstention_rate", "empty_answer_rate", "clean_service_ok_rate",
                 "answers_with_citation_rate", "avg_seconds", "avg_tokens_per_second"]


def ids_from_text(text, truncated):
    """Distinct CVE ids found by regex in the raw answer text (in order). See the module docstring."""
    text = text or ""
    end = len(text.rstrip())
    out, seen = [], set()
    for m in CVE_ANY.finditer(text):
        if truncated and m.end() >= end:
            continue
        cid = m.group(0).upper()
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def cve_facts(cve):
    """The few facts we keep from a full NVD CVE object."""
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    products = set()
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if m.get("vulnerable"):
                    parts = (m.get("criteria") or "").split(":")
                    if len(parts) > 4:
                        products.add(f"{parts[3]}:{parts[4]}")
    return {"description": desc, "products": products, "vuln_status": cve.get("vulnStatus"),
            "has_config": bool(cve.get("configurations"))}


def load_cve_facts(dirs):
    facts = {}
    for d in dirs:
        for p in glob.glob(os.path.join(d, "*.json")):
            try:
                with open(p, encoding="utf-8") as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                continue
            for v in ((rec.get("body") or {}).get("vulnerabilities") or []):
                cve = v.get("cve", {})
                if cve.get("id") and cve["id"] not in facts:
                    facts[cve["id"]] = cve_facts(cve)
    return facts


def is_bundled_library(facts):
    if not facts:
        return False
    return bool(BUNDLED_RE.search(facts["description"] or "")) or bool(facts["products"] & BUNDLED_PRODUCTS)


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Grade the models' answers following PROTOCOL.md.")
    ap.add_argument("--runs-dir", nargs="+", default=["llm_runs"], help="folders with raw_calls.jsonl (models, baseline)")
    ap.add_argument("--out-dir", default="grading")
    ap.add_argument("--truth", default=os.path.join("ground_truth", "nvd_truth.csv"))
    ap.add_argument("--summary", default=os.path.join("ground_truth", "nvd_truth_summary.csv"))
    ap.add_argument("--raw-dir", default=os.path.join("ground_truth", "nvd_raw"))
    ap.add_argument("--shortlists", default=os.path.join("prompts", "shortlists.json"))
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--delay", type=float, default=None)
    ap.add_argument("--critical", type=float, default=9.0, help="CVSS v3 score that counts as critical")
    args = ap.parse_args()

    raw_paths = [os.path.join(d, "raw_calls.jsonl") for d in args.runs_dir]
    for p in raw_paths + [args.truth, args.summary]:
        if not os.path.exists(p):
            sys.exit(f"Cannot find {p}")
    os.makedirs(args.out_dir, exist_ok=True)

    by_id = {}
    for rp in raw_paths:
        with open(rp, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    by_id[r["call_id"]] = r
                except (ValueError, KeyError):
                    pass
    calls = list(by_id.values())
    print(f"Answers to grade: {len(calls)}")

    # ---- ground truth
    truth_rows = read_csv(args.truth)
    summary_rows = read_csv(args.summary)
    family = {r["service_id"]: r["product_family"] for r in summary_rows}
    have_flags = bool(truth_rows) and "unbounded_version_match" in truth_rows[0]
    if not have_flags:
        print("[warning] nvd_truth.csv has no flag columns; run build_nvd_truth.py again (it uses its cache). "
              "Only the three entries named by the professor will be treated as disputed.")
    specific = {sid: {} for sid in family}
    truth_status = {}
    flagged_family = collections.defaultdict(set)
    flagged_service = collections.defaultdict(set)
    for r in truth_rows:
        sid, cid = r["service_id"], r["cve_id"]
        truth_status.setdefault(cid, r.get("vuln_status"))
        if have_flags and (r.get("unbounded_version_match") == "True" or "disputed" in (r.get("cve_tags") or "")):
            flagged_family[family.get(sid)].add(cid)
            flagged_service[sid].add(cid)
        elif sid in specific:
            specific[sid][cid] = to_float(r.get("cvss_v3_score"))
    flagged_family[NAMED_FAMILY] |= PROFESSOR_NAMED
    table_flagged = set().union(*flagged_service.values()) if flagged_service else set()
    print(f"Disputed / all-versions entries flagged in the truth table: {len(table_flagged)}")
    print(f"  named by the professor but not flagged in the table: {sorted(PROFESSOR_NAMED - table_flagged) or 'none'}")
    print(f"  flagged in the table but not named by the professor: {sorted(table_flagged - PROFESSOR_NAMED) or 'none'} "
          "(they are also graded as neutral; check that this is what you want)")

    shortlists = {}
    if os.path.exists(args.shortlists):
        with open(args.shortlists, encoding="utf-8") as f:
            shortlists = json.load(f)["shortlists"]

    # ---- CVE facts: from the saved NVD replies, then NVD lookups for the rest
    cache_dir = os.path.join(args.out_dir, "nvd_cve_cache")
    facts = load_cve_facts([args.raw_dir, cache_dir])
    answer_ids = {}
    cited_ids = set()
    for r in calls:
        ids = ids_from_text(r.get("response_text"), r.get("done_reason") == "length")
        answer_ids[r["call_id"]] = ids
        cited_ids.update(ids)
    unknown = sorted(c for c in cited_ids if c not in truth_status and c not in facts)
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    delay = args.delay if args.delay is not None else (0.7 if api_key else 6.2)
    client = NvdClient(args.base_url, api_key, cache_dir, delay, 1, False)
    print(f"Distinct cited CVEs: {len(cited_ids)}   known from earlier NVD replies: {len(cited_ids) - len(unknown)}   "
          f"to look up in NVD now: {len(unknown)}" + ("" if api_key else "   (no NVD_API_KEY: slow)"))
    missing_in_nvd = {}
    stamps = []
    for i, cid in enumerate(unknown, 1):
        try:
            rec = client.get_page(f"cveId={cid}")
        except RuntimeError as e:
            sys.exit(f"\nStopped: NVD could not be reached ({e}).\nLookups done so far are saved in {cache_dir}; "
                     "run the same command again to continue.")
        body = rec.get("body") or {}
        vulns = body.get("vulnerabilities") or []
        if rec["http_status"] == 200 and vulns:
            facts[cid] = cve_facts(vulns[0]["cve"])
        else:
            missing_in_nvd[cid] = {"http": rec["http_status"], "message": rec.get("message")}
        if body.get("timestamp"):
            stamps.append(body["timestamp"])
        if i % 25 == 0 or i == len(unknown):
            print(f"  looked up {i}/{len(unknown)}")
    odd = [c for c, v in missing_in_nvd.items() if v["message"]]
    if odd:
        print(f"[note] {len(odd)} cited CVEs came back not-found with an NVD message header; example: {odd[0]} -> "
              f"{missing_in_nvd[odd[0]]['message']}. Check that this means 'no such CVE'.")

    def exists(cid):
        return cid in truth_status or cid in facts

    def status_of(cid):
        return truth_status.get(cid) if cid in truth_status else (facts.get(cid) or {}).get("vuln_status")

    def is_rejected(cid):
        f = facts.get(cid)
        return bool(f) and (f["vuln_status"] == "Rejected" or f["description"].startswith("** REJECT **"))

    def is_unscored(cid):
        if cid in truth_status:
            return truth_status[cid] in UNSCORED_STATUSES
        f = facts.get(cid)
        return bool(f) and (f["vuln_status"] in UNSCORED_STATUSES or not f["has_config"])

    # ---- the truth that grading uses: version-specific, minus MySQL bundled-library entries (neutral)
    truth_eff, bundled_in_truth = {}, collections.defaultdict(list)
    for sid, d in specific.items():
        if family.get(sid) == MYSQL_FAMILY:
            keep = {}
            for cid, sc in d.items():
                if is_bundled_library(facts.get(cid)):
                    bundled_in_truth[sid].append(cid)
                else:
                    keep[cid] = sc
            truth_eff[sid] = keep
        else:
            truth_eff[sid] = dict(d)
    if bundled_in_truth:
        print("MySQL ground-truth entries treated as neutral (bundled third-party library): " +
              ", ".join(f"{s}: {len(v)} of {len(specific[s])}" for s, v in sorted(bundled_in_truth.items())))

    # ---- grade
    cit_rows, call_rows = [], []
    neutral_seen = {}
    for r in calls:
        sid, cond, pid = r["service_id"], r["condition"], r["prompt"]
        fam = family.get(sid) or ("OpenSSH" if sid.startswith("openssh") else sid.split("_")[0])
        p = r.get("parsed")
        valid = isinstance(p, dict) and isinstance(p.get("cves"), list)
        truncated = r.get("done_reason") == "length"
        conf = {}
        if valid:
            for c in p["cves"]:
                if isinstance(c, dict) and c.get("cve_id"):
                    conf.setdefault(str(c["cve_id"]).strip().upper(), c.get("confidence", ""))
        sl = {it["cve_id"]: it["decoy_type"] for it in shortlists.get(sid, {}).get("items", [])} if pid == "c" else {}
        truth_ids = truth_eff.get(sid, {}) if cond == "complete" else None
        counts, neutral_counts = collections.Counter(), collections.Counter()
        correct_critical = 0
        cited = answer_ids[r["call_id"]]
        for cid in cited:
            reason = ""
            if not exists(cid):
                label = "fabricated"
            elif is_rejected(cid):
                label = "rejected"
            elif cond != "complete":
                label = "real_unsupported"
            elif cid in flagged_family.get(fam, set()) or cid in flagged_service.get(sid, set()):
                label, reason = "neutral", "disputed_or_all_versions"
            elif fam == MYSQL_FAMILY and is_bundled_library(facts.get(cid)):
                label, reason = "neutral", "mysql_bundled_library"
            elif cid in truth_ids:
                label = "correct"
            elif is_unscored(cid):
                label = "real_unscored"
            else:
                label = "real_but_wrong"
            counts[label] += 1
            if reason:
                neutral_counts[reason] += 1
                neutral_seen.setdefault((fam, cid, reason), {"scope": "cited", "times_cited": 0})["times_cited"] += 1
            if label == "correct" and (truth_ids.get(cid) or 0) >= args.critical:
                correct_critical += 1
            cit_rows.append({
                "call_id": r["call_id"], "model": r["model"], "prompt": pid, "condition": cond, "service_id": sid,
                "run": r["run"], "run_type": run_type(r["run"]), "answer_valid": valid, "cve_id": cid,
                "confidence": conf.get(cid, ""), "label": label, "neutral_reason": reason,
                "nvd_vuln_status": status_of(cid) or "",
                "shortlist_type": (sl.get(cid, "outside_list") if pid == "c" else ""),
            })
        n_cited = len(cited)
        truth_size = len(truth_ids) if truth_ids is not None else None
        n_missing = max(truth_size - counts["correct"], 0) if truth_size is not None else None
        if truth_size is None:
            outcome = "no_ground_truth_empty" if n_cited == 0 else "no_ground_truth_cited"
        elif truth_size == 0:
            outcome = "clean_service_correct_empty" if n_cited == 0 else "clean_service_cited"
        else:
            outcome = "empty_answer_missed_all" if n_cited == 0 else "answered"
        ev = (r["eval_count"] / (r["eval_duration_ns"] / 1e9)) if r.get("eval_count") and r.get("eval_duration_ns") else None
        call_rows.append({
            "call_id": r["call_id"], "model": r["model"], "prompt": pid, "condition": cond, "service_id": sid,
            "run": r["run"], "run_type": run_type(r["run"]), "valid": valid, "truncated": truncated,
            "not_sure": bool(valid and p.get("not_sure") is True), "n_cited": n_cited,
            **{f"n_{l}": counts[l] for l in LABELS},
            "n_neutral_disputed": neutral_counts["disputed_or_all_versions"],
            "n_neutral_bundled": neutral_counts["mysql_bundled_library"],
            "truth_size": truth_size,
            "critical_truth_size": (sum(1 for v in truth_ids.values() if v is not None and v >= args.critical)
                                    if truth_ids is not None else None),
            "correct_critical": correct_critical, "n_missing": n_missing, "empty_answer": n_cited == 0,
            "clean_service": (truth_size == 0) if truth_size is not None else None, "answer_outcome": outcome,
            "cited_ids": ";".join(cited), "wall_seconds": r.get("wall_seconds"),
            "tokens_per_second": round(ev, 2) if ev else None,
        })

    def out_rows(rows):
        return [{k: ("" if v is None else v) for k, v in x.items()} for x in rows]

    cit_fields = ["call_id", "model", "prompt", "condition", "service_id", "run", "run_type", "answer_valid", "cve_id",
                  "confidence", "label", "neutral_reason", "nvd_vuln_status", "shortlist_type"]
    write_csv(os.path.join(args.out_dir, "graded_citations.csv"), cit_fields, cit_rows)
    call_fields = ["call_id", "model", "prompt", "condition", "service_id", "run", "run_type", "valid", "truncated",
                   "not_sure", "n_cited"] + [f"n_{l}" for l in LABELS] + [
        "n_neutral_disputed", "n_neutral_bundled", "truth_size", "critical_truth_size", "correct_critical", "n_missing",
        "empty_answer", "clean_service", "answer_outcome", "cited_ids", "wall_seconds", "tokens_per_second"]
    write_csv(os.path.join(args.out_dir, "graded_calls.csv"), call_fields, out_rows(call_rows))

    # ---- review file for the neutral rules
    review = []
    for sid, ids in sorted(bundled_in_truth.items()):
        for cid in ids:
            review.append({"scope": "ground truth", "family": MYSQL_FAMILY, "service_id": sid, "cve_id": cid,
                           "reason": "mysql_bundled_library", "times_cited": "",
                           "description": (facts[cid]["description"] or "")[:240]})
    for (fam, cid, reason), v in sorted(neutral_seen.items()):
        review.append({"scope": "cited", "family": fam, "service_id": "", "cve_id": cid, "reason": reason,
                       "times_cited": v["times_cited"],
                       "description": ((facts.get(cid) or {}).get("description") or "")[:240]})
    write_csv(os.path.join(args.out_dir, "neutral_review.csv"),
              ["scope", "family", "service_id", "cve_id", "reason", "times_cited", "description"], review)

    # ---- summaries
    groups = collections.defaultdict(list)
    for x in call_rows:
        groups[(x["model"], x["prompt"], x["condition"], x["run_type"])].append(x)
    sc_rows = []
    for k, rows in sorted(groups.items()):
        m = metrics(rows)
        if k[1] == "c":
            kk = [c for c in cit_rows if (c["model"], c["prompt"], c["condition"], c["run_type"]) == k]
            m["c_selected_same_family_decoys"] = sum(1 for c in kk if c["shortlist_type"] == "same_family_other_version")
            m["c_selected_other_product_decoys"] = sum(1 for c in kk if c["shortlist_type"] == "other_product")
            m["c_cited_outside_list"] = sum(1 for c in kk if c["shortlist_type"] == "outside_list")
        sc_rows.append({"model": k[0], "prompt": k[1], "condition": k[2], "run_type": k[3], **m})
    extra = ["c_selected_same_family_decoys", "c_selected_other_product_decoys", "c_cited_outside_list"]
    write_csv(os.path.join(args.out_dir, "summary_by_condition.csv"),
              ["model", "prompt", "condition", "run_type"] + METRIC_FIELDS + extra, sc_rows)
    sg = collections.defaultdict(list)
    for x in call_rows:
        sg[(x["model"], x["prompt"], x["condition"], x["run_type"], x["service_id"])].append(x)
    write_csv(os.path.join(args.out_dir, "summary_by_service.csv"),
              ["model", "prompt", "condition", "run_type", "service_id"] + METRIC_FIELDS,
              [{"model": k[0], "prompt": k[1], "condition": k[2], "run_type": k[3], "service_id": k[4], **metrics(rows)}
               for k, rows in sorted(sg.items())])

    st_rows, sets = [], collections.defaultdict(dict)
    for x in call_rows:
        if x["run_type"] == "t07":
            sets[(x["model"], x["prompt"], x["condition"], x["service_id"])][x["run"]] = set(filter(None, x["cited_ids"].split(";")))
    for k, d in sorted(sets.items()):
        if len(d) < 2:
            st_rows.append({"model": k[0], "prompt": k[1], "condition": k[2], "service_id": k[3], "runs": len(d), "mean_jaccard": ""})
            continue
        js = [1.0 if not (a | b) else len(a & b) / len(a | b) for a, b in itertools.combinations(d.values(), 2)]
        st_rows.append({"model": k[0], "prompt": k[1], "condition": k[2], "service_id": k[3], "runs": len(d),
                        "mean_jaccard": round(sum(js) / len(js), 4)})
    write_csv(os.path.join(args.out_dir, "stability.csv"), ["model", "prompt", "condition", "service_id", "runs", "mean_jaccard"], st_rows)
    ss = collections.defaultdict(list)
    for s in st_rows:
        if s["mean_jaccard"] != "":
            ss[(s["model"], s["prompt"], s["condition"])].append(s["mean_jaccard"])
    write_csv(os.path.join(args.out_dir, "stability_summary.csv"), ["model", "prompt", "condition", "services", "mean_jaccard"],
              [{"model": k[0], "prompt": k[1], "condition": k[2], "services": len(v), "mean_jaccard": round(sum(v) / len(v), 4)}
               for k, v in sorted(ss.items())])

    stamps_sorted = sorted(stamps)
    meta = {
        "graded_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "protocol": "PROTOCOL.md v1.1 (grading rules)", "answers_graded": len(calls), "citations_graded": len(cit_rows),
        "raw_calls_sha256": {p: sha256_file(p) for p in raw_paths}, "truth_csv_sha256": sha256_file(args.truth),
        "nvd_lookups_for_cited_cves": len(unknown),
        "nvd_response_timestamps": {"first": stamps_sorted[0] if stamps_sorted else None, "last": stamps_sorted[-1] if stamps_sorted else None},
        "flagged_entries_in_truth_table": sorted(table_flagged), "professor_named_entries": sorted(PROFESSOR_NAMED),
        "mysql_bundled_words": BUNDLED_WORDS, "mysql_bundled_products": sorted(BUNDLED_PRODUCTS),
        "mysql_truth_entries_made_neutral": {s: len(v) for s, v in bundled_in_truth.items()},
        "critical_cvss_threshold": args.critical,
        "notes": [
            "CVE ids are extracted by regular expression from the raw text of every answer, including invalid JSON; in an answer "
            "cut off by the length limit, an id touching the end of the text is ignored.",
            "Rates use all citations except neutral ones as the denominator; recall uses all answers on services with a non-empty "
            "effective ground truth; abstention rate = not_sure true / all answers.",
            "Effective ground truth = version-specific NVD entries, minus MySQL bundled-library entries (neutral).",
            "Duplicate CVEs within one answer are counted once.",
        ],
        "notice": "This product uses the NVD API but is not endorsed or certified by the NVD.",
    }
    with open(os.path.join(args.out_dir, "grading_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    # ---- console summary
    def pct(x):
        return "-" if x == "" else f"{100 * x:.0f}"

    def f2(x):
        return "-" if x == "" else f"{x:.2f}"
    print("\n=== Summary (complete condition; rates exclude neutral citations) ===")
    print(f"{'model':<20}{'p':<2}{'run':<5}{'calls':>6}{'cited':>6}{'corr':>6}{'wrong':>6}{'fabr':>6}{'neut':>5}"
          f"{'fabr%':>7}{'prec':>6}{'rec':>6}{'abst%':>7}")
    for r in sc_rows:
        if r["condition"] == "complete":
            print(f"{r['model']:<20}{r['prompt']:<2}{r['run_type']:<5}{r['calls']:>6}{r['citations']:>6}{r['correct']:>6}"
                  f"{r['real_but_wrong']:>6}{r['fabricated']:>6}{r['neutral_citations']:>5}{pct(r['fabricated_rate']):>7}"
                  f"{f2(r['precision']):>6}{f2(r['recall']):>6}{pct(r['abstention_rate']):>7}")
    inc = [r for r in sc_rows if r["condition"] == "incomplete"]
    if inc:
        print("\n=== Incomplete input (no version in the scan line) ===")
        print(f"{'model':<20}{'p':<2}{'run':<5}{'calls':>6}{'abstain%':>9}{'cited':>6}{'fabr':>6}{'unsupp':>7}{'citing%':>9}")
        for r in inc:
            print(f"{r['model']:<20}{r['prompt']:<2}{r['run_type']:<5}{r['calls']:>6}{pct(r['abstention_rate']):>9}"
                  f"{r['citations']:>6}{r['fabricated']:>6}{r['real_unsupported']:>7}{pct(r['answers_with_citation_rate']):>9}")
    print(f"\nFiles written to {args.out_dir}/  (review neutral_review.csv: it lists every CVE treated as neutral)")


if __name__ == "__main__":
    main()
