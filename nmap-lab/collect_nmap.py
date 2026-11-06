#!/usr/bin/env python3
"""
collect_nmap.py - collect Nmap service-detection data for the Nmap-to-CVE study.

What it does
  1. Reads lab_manifest.csv (one row per Docker service: id, role, image, port, expected version,
     and an optional nse_script column for products whose version plain -sV cannot read, e.g. Redis).
  2. Runs `nmap -sV` against each service port and saves the raw Nmap XML.
  3. Converts every result into a clean record and writes:
       results/nmap_results.json   (main dataset, hand this one to the professor)
       results/nmap_results.csv    (same data, flat, opens in Excel)
       results/raw_xml/<id>.xml    (untouched Nmap output, as evidence)
  4. Records the Docker image digest of every service (reproducibility), if Docker is available.
  5. Prints a summary and flags any service where Nmap's detected version differs
     from the version we intended to run.

Why XML and not JSON from Nmap directly: Nmap has no official JSON output.
It writes XML (-oX), and this script converts the XML to JSON.

Only standard-library Python is needed. Run:
    python collect_nmap.py
    python collect_nmap.py --manifest lab_manifest.csv --host 127.0.0.1 --out-dir results

Only scan systems you own. The default target is your own machine (127.0.0.1).
"""

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


# ----------------------------------------------------------------------------
# CPE helpers
# ----------------------------------------------------------------------------
def _escape_cpe23(value: str) -> str:
    """Escape a CPE 2.3 component: keep letters, digits, _ - . ; backslash the rest."""
    out = []
    for ch in value:
        if ch.isalnum() or ch in "_-.":
            out.append(ch)
        else:
            out.append("\\" + ch)
    return "".join(out)


def cpe22_to_23(cpe: str):
    """
    Nmap prints CPE in the older 2.2 URI form, e.g. cpe:/a:apache:http_server:2.4.49
    The NVD API needs the 2.3 form: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    if not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None
    from urllib.parse import unquote
    parts = cpe[5:].split(":")
    raw = [unquote(p) for p in parts]
    # NVD writes OpenSSH "9.6p1" as version "9.6" + update "p1"; split it so lookups match.
    if len(raw) >= 4 and raw[1:3] == ["openbsd", "openssh"]:
        m = re.match(r"^(\d+\.\d+)(p\d+)$", raw[3])
        if m:
            raw[3:4] = [m.group(1), m.group(2)]
    parts = ["*" if p == "" else _escape_cpe23(p) for p in raw]
    parts += ["*"] * (11 - len(parts))  # part, vendor, product, version, update, edition,
    return "cpe:2.3:" + ":".join(parts[:11])  # language, sw_edition, target_sw, target_hw, other


# ----------------------------------------------------------------------------
# Docker image digest (so the exact image can be reproduced later)
# ----------------------------------------------------------------------------
def get_image_digest(image):
    """
    Returns the registry digest (repo@sha256:...) for pulled images, or "local-build:sha256:..."
    (the image ID) for images built locally, or None if Docker or the image is unavailable.
    """
    if not image or not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}|{{.Id}}", image],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return None
        digests_json, _, image_id = proc.stdout.strip().partition("|")
        digests = json.loads(digests_json) if digests_json else []
        if digests:
            return digests[0]
        return f"local-build:{image_id}" if image_id else None
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None


# ----------------------------------------------------------------------------
# Nmap running and parsing
# ----------------------------------------------------------------------------
def run_nmap(nmap_path, host, port, xml_path, intensity, timeout, nse_script=""):
    """
    -sV : service/version detection (the whole point)
    -sT : plain TCP connect scan; works without admin rights and on localhost (also on Windows)
    -Pn : do not ping first, just scan the port
    -n  : no DNS lookups
    --script <name> (only when the manifest asks for it): Nmap's own script for that product
    """
    cmd = [
        nmap_path, "-sV", "-sT", "-Pn", "-n",
        "--version-intensity", str(intensity),
        "-p", str(port), "-oX", xml_path, host,
    ]
    if nse_script:
        # e.g. redis-info: an Nmap script that makes -sV report the version for products
        # whose version the plain probe does not read.
        cmd[1:1] = ["--script", nse_script]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = proc.returncode == 0 and os.path.exists(xml_path)
        return ok, cmd, (proc.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return False, cmd, f"timed out after {timeout}s"


def version_matches(expected, detected):
    """True/False if we can compare, None if we have nothing to compare."""
    if not expected:
        return None
    if not detected:
        return False
    pattern = r"(?<![\d.])" + re.escape(expected) + r"(?![\d])"
    return re.search(pattern, detected) is not None


def parse_nmap_xml(xml_path, entry, host_arg, command, image_digest=None):
    """Turn one Nmap XML file into a list of records (one per port found)."""
    root = ET.parse(xml_path).getroot()
    finished = root.find("runstats/finished")
    scan_meta = {
        "nmap_version": root.get("version"),
        "command": " ".join(command),
        "start_time_utc": (
            dt.datetime.fromtimestamp(int(root.get("start")), dt.timezone.utc).isoformat()
            if root.get("start") else None
        ),
        "elapsed_seconds": float(finished.get("elapsed")) if finished is not None and finished.get("elapsed") else None,
    }

    records = []
    for host in root.findall("host"):
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            svc = port.find("service")
            attrs = svc.attrib if svc is not None else {}
            cpes = [c.text for c in svc.findall("cpe")] if svc is not None else []

            cpe23_list = [c for c in (cpe22_to_23(x) for x in cpes) if c]

            name = attrs.get("name")
            product = attrs.get("product")
            version = attrs.get("version")
            extrainfo = attrs.get("extrainfo")

            # The one-line description the LLM will see as input.
            service_string = " ".join(x for x in [product, version, f"({extrainfo})" if extrainfo else None] if x)
            portnum = int(port.get("portid"))
            proto = port.get("protocol")
            state = state_el.get("state") if state_el is not None else None
            llm_input = f"{portnum}/{proto} {state} {name or 'unknown'}" + (f" {service_string}" if service_string else "")

            records.append({
                "id": entry["id"],
                "product_family": entry["product_family"],
                "role": entry["role"],
                "docker_image": entry["docker_image"],
                "image_digest": image_digest,
                "expected_version": entry["expected_version"] or None,
                "nse_script": entry.get("nse_script") or None,
                "host": host_arg,
                "port": portnum,
                "protocol": proto,
                "state": state,
                "service_name": name,
                "product": product,
                "detected_version": version,
                "extrainfo": extrainfo,
                "ostype": attrs.get("ostype"),
                "detection_method": attrs.get("method"),
                "detection_confidence": int(attrs["conf"]) if attrs.get("conf") else None,
                "cpe": cpes,
                "cpe23": cpe23_list,
                "cpe23_primary": next((c for c in cpe23_list if c.startswith("cpe:2.3:a:")), None),
                "nmap_service_string": service_string or None,
                "llm_input_text": llm_input,
                "version_match": version_matches(entry["expected_version"], version),
                "scan": scan_meta,
            })
    return records


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def read_manifest(path):
    required = {"id", "product_family", "role", "docker_image", "expected_version", "host_port"}
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = required - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"Manifest {path} is missing columns: {', '.join(sorted(missing))}")
        rows = [{k: (v or "").strip() for k, v in r.items()} for r in reader]
        for r in rows:
            r.setdefault("nse_script", "")
    return [r for r in rows if r["id"]]


def main():
    ap = argparse.ArgumentParser(description="Collect Nmap -sV data for the lab services.")
    ap.add_argument("--manifest", default="lab_manifest.csv")
    ap.add_argument("--host", default="127.0.0.1", help="where the Docker ports are published")
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--nmap", default="nmap", help='path to nmap, e.g. "C:\\Program Files (x86)\\Nmap\\nmap.exe"')
    ap.add_argument("--intensity", type=int, default=7, help="Nmap --version-intensity 0-9 (9 = most thorough)")
    ap.add_argument("--timeout", type=int, default=180, help="seconds allowed per service scan")
    args = ap.parse_args()

    nmap_path = shutil.which(args.nmap) or (args.nmap if os.path.exists(args.nmap) else None)
    if not nmap_path:
        sys.exit("Nmap not found. Install it from nmap.org or pass --nmap with the full path.")

    entries = read_manifest(args.manifest)
    xml_dir = os.path.join(args.out_dir, "raw_xml")
    os.makedirs(xml_dir, exist_ok=True)

    all_records, failures = [], []
    for e in entries:
        xml_path = os.path.join(xml_dir, f"{e['id']}.xml")
        print(f"[scan] {e['id']:<14} port {e['host_port']:<6} ...", end=" ", flush=True)
        ok, cmd, err = run_nmap(nmap_path, args.host, e["host_port"], xml_path, args.intensity, args.timeout,
                                e.get("nse_script", ""))
        if not ok:
            print("FAILED")
            failures.append({"id": e["id"], "error": err or "nmap returned an error"})
            continue
        recs = parse_nmap_xml(xml_path, e, args.host, cmd, get_image_digest(e["docker_image"]))
        if not recs:
            print("no port data")
            failures.append({"id": e["id"], "error": "no port element in XML (host down or port filtered)"})
            continue
        all_records.extend(recs)
        print(recs[0]["llm_input_text"])

    nmap_version = all_records[0]["scan"]["nmap_version"] if all_records else None
    dataset = {
        "name": "nmap_collected_data",
        "purpose": "Nmap service-detection results for the Nmap-to-CVE hallucination study",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "nmap_version": nmap_version,
        "target_host": args.host,
        "services_in_manifest": len(entries),
        "records": len(all_records),
        "failed_services": failures,
        "field_notes": {
            "cpe": "CPE 2.2 string exactly as Nmap printed it",
            "cpe23": "same CPE converted to 2.3 form, the form the NVD API expects",
            "image_digest": "Docker image digest (repo@sha256:...) or local-build:<image id> for images built from a Dockerfile; null if Docker was unavailable",
            "nse_script": "Nmap script used in addition to -sV for this service (null = plain -sV only)",
            "cpe23_primary": "the application CPE (2.3 form) to look up in NVD; null if Nmap gave no CPE",
            "version_match": "true/false if the detected version equals the intended Docker version, null if no intended version was set",
            "llm_input_text": "the one-line text that will be given to the language model",
        },
    }

    os.makedirs(args.out_dir, exist_ok=True)
    json_path = os.path.join(args.out_dir, "nmap_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"dataset": dataset, "records": all_records}, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(args.out_dir, "nmap_results.csv")
    flat_cols = [
        "id", "product_family", "role", "docker_image", "image_digest", "expected_version", "nse_script",
        "host", "port", "protocol",
        "state", "service_name", "product", "detected_version", "extrainfo", "detection_method",
        "detection_confidence", "cpe", "cpe23", "cpe23_primary", "nmap_service_string", "llm_input_text", "version_match",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=flat_cols, extrasaction="ignore")
        w.writeheader()
        for r in all_records:
            row = dict(r)
            row["cpe"] = ";".join(r["cpe"])
            row["cpe23"] = ";".join(r["cpe23"])
            w.writerow(row)

    print("\n=== Summary ===")
    print(f"Services scanned: {len(all_records)} of {len(entries)}  |  Nmap {nmap_version}")
    print(f"JSON : {json_path}")
    print(f"CSV  : {csv_path}")
    mism = [r for r in all_records if r["version_match"] is False]
    no_ver = [r for r in all_records if not r["detected_version"]]
    if mism:
        print("\nCheck these: detected version differs from the intended one")
        for r in mism:
            print(f"  - {r['id']}: intended {r['expected_version']}, Nmap says {r['detected_version']!r}")
    if no_ver:
        print("\nNo version detected (fix the setup or exclude from the study)")
        for r in no_ver:
            print(f"  - {r['id']}: {r['llm_input_text']}")
    for fl in failures:
        print(f"\nFAILED {fl['id']}: {fl['error']}")
    if not (mism or no_ver or failures):
        print("\nAll services detected with the intended versions.")


if __name__ == "__main__":
    main()
