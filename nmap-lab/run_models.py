#!/usr/bin/env python3
"""
run_models.py - run the local models over the Nmap results and save every raw answer.

For each model, prompt (a, b, c), service and run it sends one request to Ollama and appends one line
to llm_runs/raw_calls.jsonl. It does NOT grade anything; grading is a separate step, so the prompts and
settings must be final before the full run (see PROTOCOL.md).

Full run (3 models x 3 prompts x 15 services x 4 runs = 540 calls):
    python run_models.py

Useful options:
    python run_models.py --dry-run                       print the plan and the number of calls, send nothing
    python run_models.py --services apache_old nginx_old --runs t0 --limit 6    small pilot
    python run_models.py --incomplete-json results_incomplete/nmap_results.json  add the incomplete-input run
                                                         (services without a version; prompts a and b only)

Runs: t0 = temperature 0 (seed 42); t07_r1..r3 = three repeats at temperature 0.7 (seeds 1001..1003).
Safe to stop (Ctrl+C) and start again: finished calls are skipped. Close the Docker lab first to free RAM.

Before the first call it records the Ollama version, each model's digest, whether each model fits on the
GPU, and a SHA-256 of every prompt/schema/input file in llm_runs/run_meta.json. If those files change
between sessions the script refuses to continue (use --force only if you are sure).
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time

import requests

PROTOCOL_VERSION = "0.1-draft"
DEFAULT_MODELS = ["llama3.2:3b", "phi4-mini", "qwen3.5:4b"]
THINK_OFF_MODELS = {"qwen3.5:4b"}  # these models are sent "think": false
RUNS = [("t0", 0.0, 42), ("t07_r1", 0.7, 1001), ("t07_r2", 0.7, 1002), ("t07_r3", 0.7, 1003)]
REQUIRED_KEYS = ("product", "version", "not_sure", "cves")


def utc_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_services(path, condition):
    with open(path, encoding="utf-8") as f:
        records = json.load(f)["records"]
    return [{"service_id": r["id"], "scan_result": r["llm_input_text"], "condition": condition} for r in records]


def render_user_prompt(template, scan_result, shortlist):
    candidates = ""
    if shortlist is not None:
        candidates = "\n".join(f"- {it['cve_id']}: {it['description']}" for it in shortlist["items"])
    return template.replace("{scan_result}", scan_result).replace("{candidates}", candidates)


def parse_answer(text):
    """Returns (parsed_object_or_None, error_message_or_None)."""
    if not text or not text.strip():
        return None, "empty response"
    try:
        obj = json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return None, "no JSON object found"
        try:
            obj = json.loads(m.group(0))
        except ValueError as e:
            return None, f"invalid JSON: {e}"
    if not isinstance(obj, dict):
        return None, "JSON is not an object"
    missing = [k for k in REQUIRED_KEYS if k not in obj]
    if missing:
        return obj, "missing keys: " + ", ".join(missing)
    if not isinstance(obj["cves"], list):
        return obj, "cves is not a list"
    return obj, None


class Ollama:
    def __init__(self, base_url, timeout):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()

    def get(self, path):
        r = self.s.get(self.base + path, timeout=30)
        r.raise_for_status()
        return r.json()

    def chat(self, body):
        r = self.s.post(self.base + "/api/chat", json=body, timeout=self.timeout)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def unload(self, model):
        try:
            self.s.post(self.base + "/api/chat", json={"model": model, "keep_alive": 0, "messages": []}, timeout=60)
        except requests.RequestException:
            pass


def model_info(tags, model):
    for m in tags.get("models", []):
        if m.get("name") in (model, model + ":latest"):
            return {"digest": m.get("digest"), "size_bytes": m.get("size")}
    return None


def build_body(model, system, user, schema, temperature, seed, args):
    body = {
        "model": model,
        "stream": False,
        "keep_alive": "15m",
        "format": schema,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "options": {"temperature": temperature, "seed": seed, "num_ctx": args.num_ctx, "num_predict": args.num_predict},
    }
    if model in THINK_OFF_MODELS:
        body["think"] = False
    return body


def main():
    ap = argparse.ArgumentParser(description="Run the local models and save every raw answer.")
    ap.add_argument("--nmap-json", default=os.path.join("results", "nmap_results.json"))
    ap.add_argument("--incomplete-json", default=None, help="Nmap results without versions (prompts a and b only)")
    ap.add_argument("--prompts-dir", default="prompts")
    ap.add_argument("--out-dir", default="llm_runs")
    ap.add_argument("--models", nargs="*", default=DEFAULT_MODELS)
    ap.add_argument("--prompt-ids", nargs="*", default=["a", "b", "c"])
    ap.add_argument("--runs", nargs="*", default=[r[0] for r in RUNS], help="subset of: " + " ".join(r[0] for r in RUNS))
    ap.add_argument("--services", nargs="*", help="only these service ids")
    ap.add_argument("--limit", type=int, default=None, help="stop after this many new calls")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=4096)
    ap.add_argument("--num-predict", type=int, default=1024)
    ap.add_argument("--timeout", type=int, default=900, help="seconds allowed per call (model loading included)")
    ap.add_argument("--force", action="store_true", help="continue even if prompt/input files changed")
    args = ap.parse_args()

    pdir = args.prompts_dir
    paths = {n: os.path.join(pdir, f) for n, f in [("system", "system.txt"), ("a", "prompt_a.txt"), ("b", "prompt_b.txt"),
                                                   ("c", "prompt_c.txt"), ("schema", "schema.json")]}
    for p in list(paths.values()) + [args.nmap_json]:
        if not os.path.exists(p):
            sys.exit(f"Missing file: {p} (run from the nmap-lab folder)")
    system = read_text(paths["system"])
    templates = {k: read_text(paths[k]) for k in ("a", "b", "c")}
    with open(paths["schema"], encoding="utf-8") as f:
        schema = json.load(f)

    shortlists = None
    sl_path = os.path.join(pdir, "shortlists.json")
    if "c" in args.prompt_ids:
        if not os.path.exists(sl_path):
            sys.exit(f"Missing {sl_path}. Run make_shortlists.py first (prompt c needs it).")
        with open(sl_path, encoding="utf-8") as f:
            shortlists = json.load(f)["shortlists"]

    complete = load_services(args.nmap_json, "complete")
    incomplete = load_services(args.incomplete_json, "incomplete") if args.incomplete_json else []
    if args.services:
        keep = set(args.services)
        complete = [s for s in complete if s["service_id"] in keep]
        incomplete = [s for s in incomplete if s["service_id"] in keep]
    if shortlists is not None:
        missing = [s["service_id"] for s in complete if s["service_id"] not in shortlists]
        if missing:
            sys.exit("No shortlist for: " + ", ".join(missing) + ". Re-run make_shortlists.py.")
    runs = [r for r in RUNS if r[0] in args.runs]

    # The plan: one model at a time (so each model is loaded once).
    plan = []
    for model in args.models:
        for services, prompt_ids in ((complete, args.prompt_ids), (incomplete, [p for p in args.prompt_ids if p != "c"])):
            for pid in prompt_ids:
                for run_label, temp, seed in runs:
                    for svc in services:
                        plan.append({"model": model, "prompt": pid, "run": run_label, "temperature": temp, "seed": seed, **svc,
                                     "call_id": f"{model}|{pid}|{svc['service_id']}|{run_label}"})

    os.makedirs(args.out_dir, exist_ok=True)
    raw_path = os.path.join(args.out_dir, "raw_calls.jsonl")
    err_path = os.path.join(args.out_dir, "errors.jsonl")
    meta_path = os.path.join(args.out_dir, "run_meta.json")
    done = set()
    if os.path.exists(raw_path):
        with open(raw_path, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["call_id"])
                except (ValueError, KeyError):
                    pass
    todo = [p for p in plan if p["call_id"] not in done]
    if args.limit is not None:
        todo = todo[: args.limit]

    print(f"Planned calls: {len(plan)}   already done: {len(plan) - len([p for p in plan if p['call_id'] not in done])}   "
          f"to run now: {len(todo)}")
    by = {}
    for p in plan:
        k = (p["model"], p["condition"], p["prompt"])
        by[k] = by.get(k, 0) + 1
    for (m, c, pid), n in sorted(by.items()):
        print(f"   {m:<14} {c:<10} prompt {pid}: {n} calls")
    if args.dry_run:
        return

    hashes = {n: sha256_file(p) for n, p in paths.items()}
    hashes["shortlists"] = sha256_file(sl_path) if os.path.exists(sl_path) else None
    hashes["nmap_json"] = sha256_file(args.nmap_json)
    hashes["incomplete_json"] = sha256_file(args.incomplete_json) if args.incomplete_json else None
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        old = meta.get("file_hashes", {})
        changed = [k for k, v in hashes.items() if k in old and old[k] != v and not (k == "incomplete_json" and old[k] is None)]
        if changed and not args.force:
            sys.exit("These files changed since the first session: " + ", ".join(changed) +
                     ". Mixing results from different prompts invalidates the experiment. Use a new --out-dir, "
                     "or --force if you are sure.")

    client = Ollama(args.ollama_url, args.timeout)
    try:
        version = client.get("/api/version").get("version")
        tags = client.get("/api/tags")
    except requests.RequestException as e:
        sys.exit(f"Cannot reach Ollama at {args.ollama_url}: {e}\nStart the Ollama app and try again.")
    infos = {}
    for m in sorted({p["model"] for p in todo}):
        info = model_info(tags, m)
        if not info:
            sys.exit(f"Model {m} is not installed. Run: ollama pull {m}")
        infos[m] = info

    meta.setdefault("protocol_version", PROTOCOL_VERSION)
    meta["file_hashes"] = {**meta.get("file_hashes", {}), **{k: v for k, v in hashes.items() if v}}
    meta.setdefault("models", {}).update(infos)
    meta.setdefault("gpu_fit", {})
    meta["ollama_version"] = version
    meta["settings"] = {"num_ctx": args.num_ctx, "num_predict": args.num_predict, "format": "JSON schema (prompts/schema.json)",
                        "runs": {r[0]: {"temperature": r[1], "seed": r[2]} for r in RUNS},
                        "think_off_models": sorted(THINK_OFF_MODELS), "keep_alive": "15m"}
    session = {"started_utc": utc_iso(), "planned_now": len(todo), "completed_now": 0, "errors_now": 0}
    meta.setdefault("sessions", []).append(session)

    def save_meta():
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)

    save_meta()
    raw_f = open(raw_path, "a", encoding="utf-8")
    err_f = open(err_path, "a", encoding="utf-8")
    current_model, t_start, n_done = None, time.time(), 0
    try:
        for i, p in enumerate(todo, 1):
            if p["model"] != current_model:
                if current_model:
                    client.unload(current_model)
                current_model = p["model"]
                print(f"\n=== {current_model}: loading and warming up ===")
                try:  # warm-up call (not recorded)
                    client.chat(build_body(current_model, system, "Reply with an empty list.", schema, 0.0, 42, args))
                    for lm in client.get("/api/ps").get("models", []):
                        if lm.get("name") in (current_model, current_model + ":latest"):
                            size, vram = lm.get("size") or 0, lm.get("size_vram") or 0
                            pct = round(100 * vram / size) if size else None
                            meta["gpu_fit"][current_model] = {"size_bytes": size, "size_vram_bytes": vram, "gpu_percent": pct}
                            print(f"    GPU: {pct}% of the model is in VRAM" + ("" if pct == 100 else "  (not fully on GPU: expect slower answers)"))
                    save_meta()
                except (RuntimeError, requests.RequestException) as e:
                    print(f"    warm-up failed: {e}")

            shortlist = shortlists.get(p["service_id"]) if (p["prompt"] == "c" and shortlists) else None
            user = render_user_prompt(templates[p["prompt"]], p["scan_result"], shortlist)
            body = build_body(p["model"], system, user, schema, p["temperature"], p["seed"], args)

            resp, error, wall = None, None, None
            for attempt in range(1, 4):
                t0 = time.time()
                try:
                    resp = client.chat(body)
                    wall = time.time() - t0
                    error = None
                    break
                except (RuntimeError, requests.RequestException) as e:
                    error = str(e)
                    time.sleep(5 * attempt)
            if error or resp is None:
                err_f.write(json.dumps({"call_id": p["call_id"], "timestamp_utc": utc_iso(), "error": error}) + "\n")
                err_f.flush()
                session["errors_now"] += 1
                print(f"[{i}/{len(todo)}] {p['call_id']}  ERROR: {error}")
                continue

            msg = resp.get("message", {}) or {}
            content = msg.get("content", "")
            parsed, perr = parse_answer(content)
            rec = {
                "call_id": p["call_id"], "timestamp_utc": utc_iso(), "protocol_version": PROTOCOL_VERSION,
                "condition": p["condition"], "model": p["model"], "prompt": p["prompt"], "service_id": p["service_id"],
                "run": p["run"], "temperature": p["temperature"], "seed": p["seed"], "num_ctx": args.num_ctx,
                "num_predict": args.num_predict, "think": False if p["model"] in THINK_OFF_MODELS else None,
                "scan_result": p["scan_result"], "user_prompt": user,
                "user_prompt_sha256": hashlib.sha256(user.encode("utf-8")).hexdigest(),
                "response_text": content, "thinking_text": msg.get("thinking"),
                "parsed": parsed, "parse_error": perr, "done_reason": resp.get("done_reason"),
                "wall_seconds": round(wall, 3), "total_duration_ns": resp.get("total_duration"),
                "load_duration_ns": resp.get("load_duration"), "prompt_eval_count": resp.get("prompt_eval_count"),
                "eval_count": resp.get("eval_count"), "eval_duration_ns": resp.get("eval_duration"),
            }
            raw_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            raw_f.flush()
            n_done += 1
            session["completed_now"] = n_done
            n_cves = len(parsed["cves"]) if parsed and isinstance(parsed.get("cves"), list) else "-"
            ns = parsed.get("not_sure") if parsed else "-"
            per_call = (time.time() - t_start) / n_done
            eta_min = per_call * (len(todo) - i) / 60
            print(f"[{i}/{len(todo)}] {p['model']} {p['prompt']} {p['service_id']} {p['run']}: {wall:.1f}s, "
                  f"{n_cves} CVEs, not_sure={ns}" + (f"  PARSE PROBLEM: {perr}" if perr else "") +
                  (f"  (truncated)" if rec["done_reason"] == "length" else "") + f"   ~{eta_min:.0f} min left")
    except KeyboardInterrupt:
        print("\nStopped. Run the same command again to continue where it stopped.")
    finally:
        if current_model:
            client.unload(current_model)
        session["finished_utc"] = utc_iso()
        save_meta()
        raw_f.close()
        err_f.close()

    print(f"\nThis session: {session['completed_now']} calls saved, {session['errors_now']} errors.")
    print(f"Raw answers: {raw_path}\nRun record : {meta_path}")


if __name__ == "__main__":
    main()
