#!/usr/bin/env python3
"""
build_nvd_truth.py - build the NVD ground-truth table for the Nmap-to-CVE study.

For every service in results/nmap_results.json it asks the NVD CVE API (v2.0) which CVEs apply to
the detected product/version, and writes (default folder: ground_truth/):

  nvd_truth.csv                  one row per (service, CVE): the ground truth
  nvd_truth_summary.csv          one row per service: counts, method used, anything to double-check
  nvd_crosscheck_differences.csv CVEs that the two NVD query methods disagree on (review by hand)
  nvd_truth_meta.json            query date, SHA-256 of the Nmap dataset, settings, sanity checks
  nvd_raw/                       every raw NVD reply (evidence; also used as a cache on re-runs)

How the lookup works
  Primary method : cpeName + isVulnerable  (CVEs whose vulnerable configurations include this CPE)
  Cross-check    : virtualMatchString      (a broader NVD match; used to spot disagreements)
  Because Nmap's vendor names do not always match NVD's (mysql:mysql vs oracle:mysql,
  igor_sysoev:nginx vs f5:nginx, OpenSSH's p1 update field), each service is queried under every
  alias listed in VENDOR_ALIASES / UPDATE_VARIANTS below and the results are merged. The column
  found_by shows which name found each CVE; "raw" means Nmap's CPE exactly as printed, which is
  what the non-AI baseline in the paper would use without any correction.

Extra columns: cve_tags (e.g. "disputed", taken from NVD) and unbounded_version_match (True when NVD
attaches the CVE to the product with no version limits, so it matches every version, even brand-new ones).
Decide in the experiment protocol whether such CVEs count in the truth set; the summary reports both
n_truth and n_truth_version_specific.

API key: read from the environment variable NVD_API_KEY. If it is missing, or NVD rejects it,
the script continues without a key at NVD's slower public rate (about 6 s between requests).

Run from the nmap-lab folder:
    python build_nvd_truth.py
    python build_nvd_truth.py --refresh        # ignore the cache and ask NVD again

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.parse

import requests

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SCRIPT_VERSION = "1.1"

# Nmap name (vendor, product) -> other (vendor, product) names NVD may use for the same software.
VENDOR_ALIASES = {
    ("igor_sysoev", "nginx"): [("f5", "nginx"), ("nginx", "nginx")],
    ("mysql", "mysql"): [("oracle", "mysql")],
}
# (vendor, product) -> extra values for the CPE "update" field to try when Nmap's is "*".
UPDATE_VARIANTS = {
    ("openbsd", "openssh"): ["p1"],
}

# Sanity checks from the author's memory of well-known CVEs. A CHECK result means "look at it",
# not that the script is wrong: verify on nvd.nist.gov.
KNOWN_CVES = [
    ("apache_old", "CVE-2021-41773"),
    ("nginx_old", "CVE-2021-23017"),
    ("openssh_mid", "CVE-2024-6387"),
]

TRANSIENT_STATUSES = {403, 429, 500, 502, 503, 504}


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.isoformat(timespec="seconds")


# ----------------------------------------------------------------------------
# NVD client: rate limiting, retries, raw-reply cache
# ----------------------------------------------------------------------------
class NvdClient:
    def __init__(self, base_url, api_key, cache_dir, delay, page_size, refresh):
        self.base_url = base_url
        self.api_key = api_key or ""
        self.key_rejected = False
        self.cache_dir = cache_dir
        self.delay = delay
        self.page_size = page_size
        self.refresh = refresh
        self.session = requests.Session()
        self.last_request = 0.0
        self.network_requests = 0
        self.cache_hits = 0
        os.makedirs(cache_dir, exist_ok=True)

    def _headers(self):
        h = {"User-Agent": "MASTER-2027-research-script"}
        if self.api_key and not self.key_rejected:
            h["apiKey"] = self.api_key
        return h

    def _wait(self):
        need = self.delay - (time.time() - self.last_request)
        if need > 0:
            time.sleep(need)

    def get_page(self, query_string):
        """Returns {"url", "retrieved_utc", "http_status", "message", "body"} for one API page."""
        url = f"{self.base_url}?{query_string}"
        cache_path = os.path.join(self.cache_dir, hashlib.sha1(url.encode()).hexdigest()[:20] + ".json")
        if os.path.exists(cache_path) and not self.refresh:
            with open(cache_path, encoding="utf-8") as f:
                self.cache_hits += 1
                return json.load(f)

        attempt = 0
        while True:
            self._wait()
            self.last_request = time.time()
            self.network_requests += 1
            try:
                resp = self.session.get(url, headers=self._headers(), timeout=60)
            except requests.RequestException as e:
                status, message, body = None, f"network error: {e}", None
            else:
                status = resp.status_code
                message = resp.headers.get("message")
                body = None
                if status == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        status, message = None, "reply was not valid JSON"

            # A rejected key comes back as 404 with "Invalid apiKey." in the "message" header.
            if status == 404 and message and "apikey" in message.lower():
                if self.api_key and not self.key_rejected:
                    print("  [warning] NVD rejected the API key (Invalid apiKey). Continuing without a key at the "
                          "slower public rate. Check the key, then re-run.")
                    self.key_rejected = True
                    self.delay = max(self.delay, 6.2)
                    continue
                raise RuntimeError(f"NVD answered 'Invalid apiKey' even without a key: {message}")

            if status == 200 or status == 404:
                rec = {
                    "url": url,
                    "retrieved_utc": iso(utcnow()),
                    "http_status": status,
                    "message": message,
                    "body": body,
                }
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(rec, f)
                return rec

            attempt += 1
            if attempt > 6:
                raise RuntimeError(f"NVD request kept failing (status {status}, {message}): {url}")
            wait = min(60, 10 * 2 ** (attempt - 1))
            print(f"  [retry {attempt}/6] status {status} ({message}); waiting {wait}s")
            time.sleep(wait)


def is_unbounded(cve, products):
    """
    True if NVD attaches this CVE to the product with no version limits at all (a vulnerable CPE
    match whose version is "*" and which has no versionStart/versionEnd bound). Such "all versions"
    entries match every version of the product, including very new ones, so they are flagged.
    """
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 6 or f"{parts[3]}:{parts[4]}" not in products or parts[5] != "*":
                    continue
                if any(m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                          "versionEndIncluding", "versionEndExcluding")):
                    continue
                return True
    return False


def extract_cve(cve, products=()):
    metrics = cve.get("metrics", {}) or {}
    score = severity = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score, severity = data.get("baseScore"), data.get("baseSeverity")
            break
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_v3_score": score,
        "cvss_v3_severity": severity,
        "cve_tags": sorted({t for ct in (cve.get("cveTags") or []) for t in (ct.get("tags") or [])}),
        "unbounded_version_match": is_unbounded(cve, set(products)),
    }


def build_query(kind, cpe, page_size, start):
    quoted = urllib.parse.quote(cpe, safe=":*")
    if kind == "cpeName":
        # isVulnerable and noRejected are flag parameters: they take no value.
        return f"cpeName={quoted}&isVulnerable&noRejected&resultsPerPage={page_size}&startIndex={start}"
    return f"virtualMatchString={quoted}&noRejected&resultsPerPage={page_size}&startIndex={start}"


def fetch_all(client, kind, cpe):
    """Fetch every page for one query. status: ok | not_found (NVD answered 404 for this CPE)."""
    cves, stamps, retrieved = {}, [], []
    start = 0
    cparts = cpe.split(":")
    products = {f"{cparts[3]}:{cparts[4]}"} if len(cparts) > 4 else set()
    while True:
        rec = client.get_page(build_query(kind, cpe, client.page_size, start))
        if rec["http_status"] == 404:
            return {"status": "not_found", "message": rec.get("message"), "cves": {}, "stamps": [], "retrieved": []}
        body = rec["body"] or {}
        vulns = body.get("vulnerabilities", [])
        for v in vulns:
            item = extract_cve(v.get("cve", {}), products)
            if item["cve_id"]:
                cves[item["cve_id"]] = item
        if body.get("timestamp"):
            stamps.append(body["timestamp"])
        retrieved.append(rec["retrieved_utc"])
        start += client.page_size
        if not vulns or start >= body.get("totalResults", 0):
            break
    return {"status": "ok", "message": None, "cves": cves, "stamps": stamps, "retrieved": retrieved}


def add_to_truth(truth, item, label):
    entry = truth.setdefault(item["cve_id"], {**item, "found_by": []})
    entry["found_by"].append(label)
    entry["unbounded_version_match"] = entry["unbounded_version_match"] or item["unbounded_version_match"]
    entry["cve_tags"] = sorted(set(entry["cve_tags"]) | set(item["cve_tags"]))


def build_variants(cpe):
    """(label, cpe23) pairs to query: Nmap's CPE as printed ("raw") plus known NVD naming variants."""
    parts = cpe.split(":")
    variants = [("raw", cpe)]
    if len(parts) < 7:
        return variants
    vendor, product = parts[3], parts[4]
    for v, p in VENDOR_ALIASES.get((vendor, product), []):
        q = parts[:]
        q[3], q[4] = v, p
        variants.append((f"{v}:{p}", ":".join(q)))
    if parts[6] == "*":
        for upd in UPDATE_VARIANTS.get((vendor, product), []):
            q = parts[:]
            q[6] = upd
            variants.append((f"update={upd}", ":".join(q)))
    return variants


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Build the NVD ground-truth table from nmap_results.json.")
    ap.add_argument("--nmap-json", default=os.path.join("results", "nmap_results.json"))
    ap.add_argument("--out-dir", default="ground_truth")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--page-size", type=int, default=2000, help="results per page (NVD maximum is 2000)")
    ap.add_argument("--delay", type=float, default=None,
                    help="seconds between requests (default 0.7 with a key, 6.2 without)")
    ap.add_argument("--refresh", action="store_true", help="ignore cached replies and ask NVD again")
    ap.add_argument("--no-crosscheck", action="store_true", help="skip the virtualMatchString cross-check")
    ap.add_argument("--only", nargs="*", help="only these service ids, e.g. --only apache_old nginx_old")
    args = ap.parse_args()

    if not os.path.exists(args.nmap_json):
        sys.exit(f"Cannot find {args.nmap_json}. Run collect_nmap.py first, from the nmap-lab folder.")
    with open(args.nmap_json, "rb") as f:
        raw_bytes = f.read()
    dataset_sha = hashlib.sha256(raw_bytes).hexdigest()
    records = json.loads(raw_bytes.decode("utf-8"))["records"]
    if args.only:
        records = [r for r in records if r["id"] in set(args.only)]

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    delay = args.delay if args.delay is not None else (0.7 if api_key else 6.2)
    if not api_key:
        print("[info] NVD_API_KEY not set: running at the slower public rate (about 6 s per request).")

    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    client = NvdClient(args.base_url, api_key, os.path.join(out_dir, "nvd_raw"), delay, args.page_size, args.refresh)

    started = utcnow()
    truth_rows, summary_rows, diff_rows = [], [], []
    all_stamps, all_retrieved = [], []
    truth_ids_by_service = {}

    for r in records:
        sid, cpe = r["id"], r.get("cpe23_primary")
        base = {
            "service_id": sid,
            "product_family": r.get("product_family"),
            "role": r.get("role"),
            "detected_version": r.get("detected_version"),
        }
        if not cpe:
            print(f"[skip] {sid}: Nmap reported no CPE/version, nothing to look up")
            summary_rows.append({**base, "n_truth": 0, "truth_method": "none",
                                 "needs_manual_check": True, "notes": "no CPE reported by Nmap"})
            continue

        print(f"[nvd]  {sid:<15} {cpe}")
        variants = []
        for label, vcpe in build_variants(cpe):
            c = fetch_all(client, "cpeName", vcpe)
            v = None if args.no_crosscheck else fetch_all(client, "virtualMatchString", vcpe)
            variants.append({"label": label, "cpe": vcpe, "c": c, "v": v})
            for res in (c, v):
                if res:
                    all_stamps += res["stamps"]
                    all_retrieved += res["retrieved"]

        # Decide the truth set.
        notes = []
        ok_c = [x for x in variants if x["c"]["status"] == "ok"]
        truth = {}
        if ok_c:
            method = "cpeName+isVulnerable"
            for x in ok_c:
                for item in x["c"]["cves"].values():
                    add_to_truth(truth, item, x["label"])
        else:
            ok_v = [x for x in variants if x["v"] and x["v"]["status"] == "ok"]
            if ok_v:
                method = "virtualMatchString (fallback)"
                notes.append("NVD had no CPE entry for any name variant; truth taken from virtualMatchString")
                for x in ok_v:
                    for item in x["v"]["cves"].values():
                        add_to_truth(truth, item, x["label"])
            else:
                method = "none"
                notes.append("NVD returned nothing usable for any name variant")

        not_found = [x["label"] for x in variants if x["c"]["status"] == "not_found"]
        if not_found:
            notes.append("cpeName not found in NVD for: " + ", ".join(not_found))

        virtual_ids = set()
        for x in variants:
            if x["v"] and x["v"]["status"] == "ok":
                virtual_ids |= set(x["v"]["cves"])
        truth_ids = set(truth)
        only_virtual = sorted(virtual_ids - truth_ids) if (method.startswith("cpeName") and not args.no_crosscheck) else []
        only_cpe = sorted(truth_ids - virtual_ids) if (method.startswith("cpeName") and not args.no_crosscheck) else []
        if only_virtual or only_cpe:
            notes.append(f"query methods disagree: {len(only_virtual)} only in virtualMatchString, "
                         f"{len(only_cpe)} only in cpeName")
        for cid in only_virtual:
            diff_rows.append({"service_id": sid, "cve_id": cid, "found_only_by": "virtualMatchString"})
        for cid in only_cpe:
            diff_rows.append({"service_id": sid, "cve_id": cid, "found_only_by": "cpeName+isVulnerable"})

        raw_variant = next((x for x in variants if x["label"] == "raw"), None)
        raw_ids = set(raw_variant["c"]["cves"]) if raw_variant and raw_variant["c"]["status"] == "ok" else set()

        for cid in sorted(truth):
            e = truth[cid]
            truth_rows.append({**base, **{k: e[k] for k in
                               ("cve_id", "published", "last_modified", "vuln_status", "cvss_v3_score", "cvss_v3_severity")},
                               "cve_tags": ";".join(e["cve_tags"]),
                               "unbounded_version_match": e["unbounded_version_match"],
                               "found_by": ";".join(sorted(set(e["found_by"]))),
                               "found_by_raw": cid in raw_ids})
        truth_ids_by_service[sid] = truth_ids
        unscored = sum(1 for e in truth.values() if e.get("vuln_status") in ("Awaiting Analysis", "Received", "Undergoing Analysis"))
        summary_rows.append({
            **base,
            "queried_names": ";".join(x["label"] for x in variants),
            "truth_method": method,
            "n_truth": len(truth_ids),
            "n_found_by_raw_cpe": len(raw_ids),
            "n_virtualmatch_check": len(virtual_ids) if not args.no_crosscheck else "",
            "n_only_virtualmatch": len(only_virtual) if not args.no_crosscheck else "",
            "n_only_cpename": len(only_cpe) if not args.no_crosscheck else "",
            "n_not_yet_analyzed": unscored,
            "n_all_versions_entries": sum(1 for e in truth.values() if e["unbounded_version_match"]),
            "n_disputed": sum(1 for e in truth.values() if "disputed" in e["cve_tags"]),
            "n_truth_version_specific": sum(1 for e in truth.values() if not e["unbounded_version_match"]),
            "needs_manual_check": bool(only_virtual or only_cpe or method != "cpeName+isVulnerable"),
            "notes": " | ".join(notes),
        })
        print(f"       truth: {len(truth_ids)} CVEs ({method}); raw Nmap CPE alone finds {len(raw_ids)}"
              + (f"; NOTE: {' | '.join(notes)}" if notes else ""))

    finished = utcnow()

    truth_fields = ["service_id", "product_family", "role", "detected_version", "cve_id", "published",
                    "last_modified", "vuln_status", "cvss_v3_score", "cvss_v3_severity", "cve_tags",
                    "unbounded_version_match", "found_by", "found_by_raw"]
    write_csv(os.path.join(out_dir, "nvd_truth.csv"), truth_fields, truth_rows)
    summary_fields = ["service_id", "product_family", "role", "detected_version", "queried_names", "truth_method",
                      "n_truth", "n_found_by_raw_cpe", "n_virtualmatch_check", "n_only_virtualmatch",
                      "n_only_cpename", "n_not_yet_analyzed", "n_all_versions_entries", "n_disputed",
                      "n_truth_version_specific", "needs_manual_check", "notes"]
    write_csv(os.path.join(out_dir, "nvd_truth_summary.csv"), summary_fields, summary_rows)
    write_csv(os.path.join(out_dir, "nvd_crosscheck_differences.csv"),
              ["service_id", "cve_id", "found_only_by"], diff_rows)

    sanity = []
    for sid, cid in KNOWN_CVES:
        if sid in truth_ids_by_service:
            sanity.append({"service_id": sid, "cve_id": cid,
                           "result": "PASS" if cid in truth_ids_by_service[sid] else "CHECK"})

    stamps_sorted = sorted(s for s in all_stamps if s)
    meta = {
        "script": "build_nvd_truth.py",
        "script_version": SCRIPT_VERSION,
        "query_started_utc": iso(started),
        "query_finished_utc": iso(finished),
        "nvd_response_timestamps": {"first": stamps_sorted[0] if stamps_sorted else None,
                                    "last": stamps_sorted[-1] if stamps_sorted else None},
        "raw_reply_retrieval_times_utc": {"first": min(all_retrieved) if all_retrieved else None,
                                          "last": max(all_retrieved) if all_retrieved else None},
        "nmap_dataset_file": args.nmap_json,
        "nmap_dataset_sha256": dataset_sha,
        "api_key_used": bool(api_key) and not client.key_rejected and client.network_requests > 0,
        "api_key_rejected_by_nvd": client.key_rejected,
        "network_requests_this_run": client.network_requests,
        "cache_hits_this_run": client.cache_hits,
        "base_url": args.base_url,
        "page_size": args.page_size,
        "primary_method": "cpeName with isVulnerable and noRejected",
        "cross_check_method": None if args.no_crosscheck else "virtualMatchString with noRejected",
        "vendor_aliases": {f"{k[0]}:{k[1]}": [f"{a}:{b}" for a, b in v] for k, v in VENDOR_ALIASES.items()},
        "update_variants": {f"{k[0]}:{k[1]}": v for k, v in UPDATE_VARIANTS.items()},
        "sanity_checks_from_author_memory": sanity,
        "notice": "This product uses the NVD API but is not endorsed or certified by the NVD.",
    }
    with open(os.path.join(out_dir, "nvd_truth_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print("\n=== Summary ===")
    print(f"Services processed: {len(summary_rows)}   CVE rows in truth table: {len(truth_rows)}")
    print(f"Network requests: {client.network_requests}   cache hits: {client.cache_hits}   "
          f"API key {'rejected by NVD' if client.key_rejected else ('used' if api_key else 'not set')}")
    print(f"Record this date in the paper (NVD data retrieved): "
          f"{(stamps_sorted[-1] if stamps_sorted else iso(finished))}")
    print(f"Nmap dataset SHA-256: {dataset_sha}")
    for s in sanity:
        print(f"  sanity {s['result']}: {s['cve_id']} for {s['service_id']}")
    flagged = [s["service_id"] for s in summary_rows if s.get("needs_manual_check")]
    if flagged:
        print("Review by hand on nvd.nist.gov (see nvd_truth_summary.csv notes): " + ", ".join(flagged))
    print(f"Files written to: {out_dir}")


if __name__ == "__main__":
    main()