# Experiment Protocol (v1.0)

**Status: FROZEN for the full run (v1.0, 2026-11-07).** The professor approved the prompts and JSON format, the candidate lists for prompt (c), the run settings, and the incomplete-input test, and decided how to treat the disputed OpenSSH entries (D1). The version is tagged `protocol-v1`. Any change after the first full-run call requires a new output folder and a new protocol version, because results produced with different prompts or settings cannot be mixed.

Section 11 lists the decisions and their status.

## 1. Purpose

The study asks whether small language models running locally can map an Nmap service-detection result to the CVEs that apply to it without making things up. Each model receives the one-line Nmap result for a service, proposes CVE identifiers, and every proposed identifier is checked against the National Vulnerability Database (NVD).

## 2. Inputs

| Input | File | Notes |
|---|---|---|
| Nmap results (15 services) | `results/nmap_results.json` | The model input is the `llm_input_text` field of each record. |
| Ground truth | `ground_truth/nvd_truth.csv` | Built by `build_nvd_truth.py`; NVD data retrieved 2026-11-06. |
| Prompt files | `prompts/system.txt`, `prompt_a.txt`, `prompt_b.txt`, `prompt_c.txt` | The exact text sent to the models. |
| Output format | `prompts/schema.json` | JSON schema enforced through Ollama. |
| Candidate lists for prompt (c) | `prompts/shortlists.json` | Built by `make_shortlists.py` with a fixed seed. |
| Incomplete inputs (optional) | `results_incomplete/nmap_results.json` | Redis services scanned without the version-reporting script. |

The SHA-256 of every input file is stored in `llm_runs/run_meta.json` at the start of the run. The runner refuses to continue if a file changes between sessions.

## 3. Models and settings

| Item | Value |
|---|---|
| Models | `llama3.2:3b`, `phi4-mini`, `qwen3.5:4b` (served by Ollama; digests recorded in `run_meta.json`) |
| Quantization | Each model's default Ollama build; not changed |
| Context length | 4096 tokens for all models |
| Maximum answer length | 1024 tokens; an answer cut off by this limit is recorded as truncated |
| Output format | JSON schema in the request (`format`) |
| Thinking mode | Off for `qwen3.5:4b` (`think: false`). The other two models have no such setting. |
| Other sampling settings | Each model's Ollama defaults, except temperature and seed |
| Runs per condition | `t0`: temperature 0, seed 42. `t07_r1`, `t07_r2`, `t07_r3`: temperature 0.7, seeds 1001, 1002, 1003 |
| Loading | One model at a time; a warm-up call before the first recorded call (not recorded); Docker lab stopped during the runs |
| Recorded per call | Exact prompt, raw answer, parsed answer, parse error, finish reason, wall time, token counts, timings |

Whether each model fits on the GPU is recorded after loading (`gpu_fit` in `run_meta.json`), since this affects response time.

## 4. Prompt conditions

The three prompts share the system message in `prompts/system.txt`. The scan line is inserted at `{scan_result}`.

| Prompt | What it asks | Difference from (a) |
|---|---|---|
| (a) direct | List the known CVEs that affect this exact product and version. | none |
| (b) abstain | Same, plus: list a CVE only if confident it exists and applies, do not invent numbers, and answer "not sure" with an empty list if the product or version is not identified. | adds the abstention instruction |
| (c) shortlist | Same scan line plus a list of candidate CVEs (id and first sentence of the NVD description); select only from the list, or select none. | adds the candidate list and the restriction |

The exact wording is in `prompts/prompt_a.txt`, `prompt_b.txt`, and `prompt_c.txt`.

## 5. Output format

Every answer must be a JSON object with these fields (`prompts/schema.json`):

- `product`: the product the model identified (empty string if none)
- `version`: the version the model identified (empty string if none)
- `not_sure`: true if the model declines to answer
- `cves`: a list of `{cve_id, confidence}`, where confidence is `high`, `medium`, or `low`

An answer that is not valid JSON or lacks a required field is kept and recorded with its parse error. It is reported as an invalid output, not silently dropped.

## 6. Run matrix

| Condition | Services | Prompts | Models | Runs | Calls |
|---|---|---|---|---|---|
| Main | 15 | a, b, c | 3 | 4 | 540 |
| Incomplete input (optional) | 3 | a, b | 3 | 4 | 72 |

The incomplete-input condition uses prompts (a) and (b) only, because prompt (c) needs a candidate list built from a known version.

## 7. Candidate lists for prompt (c)

For every service, one fixed list of 10 candidates is built (the same list for every model and run):

- Up to 5 real answers, chosen at random with a fixed seed from the CVEs that NVD attaches to this exact version. Only unambiguous entries are used: not "all versions" entries and not entries tagged disputed.
- The remaining candidates are decoys that do not apply to the service: about half are real CVEs of the same product family that apply to other versions, and the rest are real CVEs of other products.
- Services with no applicable CVEs (for example the latest versions) get decoys only, so the correct answer is to select nothing.
- The list is shuffled with the same seed. The models see only the id and the first sentence of the description. The file `prompts/shortlists_preview.csv` shows the lists, with the answer flags, in a readable table.

## 8. Incomplete-input condition (optional)

The Redis services are scanned a second time without the `redis-info` script, so the scan line has no version (for example `8010/tcp open redis Redis key-value store`). This tests how the models handle missing information. The correct behavior is to abstain. Any CVE cited for such an input is an unsupported claim, because the applicable CVEs depend on the version.

## 9. Grading rules

Each cited CVE is normalized (upper case, duplicates within an answer removed) and checked in this order:

1. The identifier is malformed (does not match `CVE-YYYY-NNNN...`), or NVD has no record of it: **fabricated**.
2. NVD records it as rejected: **rejected** (reported separately; included in the overall rate of incorrect citations but not in the fabricated rate).
3. It is one of the NVD entries that apply to all versions of the product or are tagged disputed (flagged in the truth table; the professor named three OpenSSH entries, CVE-2007-2768, CVE-2008-3844, and CVE-2023-51767): **disputed**. It is counted as neither correct nor wrong and is reported separately. The grader lists every flagged entry so the list can be checked against these three.
4. It is in the ground-truth set of the service: **correct**.
5. It exists in NVD but is not in the ground-truth set:
   - NVD has no applicability data for it (for example it is still awaiting analysis): **real, unscored**.
   - Otherwise: **real but wrong**.

The ground-truth set used for grading is the set of **version-specific** NVD entries for the exact detected version (D1).

**Missing** CVEs are the ground-truth CVEs that the answer does not cite. They are counted for recall, not as a label on a citation.

For the incomplete-input condition there is no ground-truth set. A cited CVE is labeled only as fabricated, rejected, or real (an unsupported claim), and abstention is the expected answer.

A CVE selected from the prompt (c) list is graded in the same way.

## 10. Metrics

Metrics are computed per model, per prompt, and per run type (the `t0` run, and the three `t07` runs pooled), and also per service.

| Metric | Definition | When undefined |
|---|---|---|
| Fabricated rate | fabricated citations / all citations except disputed | no such citations |
| Real-but-wrong rate | real-but-wrong citations / all citations except disputed | no such citations |
| Precision | correct citations / all citations except disputed | no such citations |
| Disputed citations | number of disputed citations (reported separately, not part of the rates above) | never |
| Recall | correct citations / size of the version-specific ground-truth set | empty ground-truth set |
| Abstention rate | answers with `not_sure` true / all answers | never |
| Invalid-output rate | unparseable or truncated answers / all answers | never |
| Stability | for each service and condition, the mean pairwise Jaccard similarity of the CVE sets across the three `t07` runs (two empty sets count as 1) | fewer than two valid runs |
| Response time | wall-clock seconds per call and generated tokens per second, from the recorded timings | never |

Services with an empty ground-truth set (the latest versions of Apache, nginx, MySQL, and Redis) are reported with the rates that do not depend on the ground truth: fabricated rate, real-but-wrong rate, and abstention rate.

**Baselines.** (1) Raw CPE baseline: Nmap's CPE exactly as printed, looked up in NVD (`found_by_raw` in the truth table). (2) Corrected baseline: the CPE looked up under the known vendor aliases, which is the ground truth itself and therefore an upper bound, not a competitor. Both baselines return only real NVD records, so they have no fabricated citations by construction.

## 11. Decisions

| # | Decision | Status |
|---|---|---|
| D1 | NVD entries that apply to all versions or are disputed | **Decided by the professor (2026-11-07):** version-specific entries are the primary ground truth; a cited entry of the disputed kind is labeled disputed, counted as neither correct nor wrong, and reported separately |
| D2 | Recall reporting | Default in force until the professor objects: recall on all version-specific CVEs, plus a second recall on critical-severity CVEs only (CVSS v3 score 9.0 or higher) |
| D3 | Rejected and real-but-unscored citations | Default in force: separate labels as in Section 9 |
| D4 | Aggregation | Default in force: pooled citations within each model, prompt, and run type, plus per-service tables |
| D5 | Prompt (c) design | Approved 2026-11-07 |
| D6 | Incomplete-input condition | Approved 2026-11-07 |
| D7 | Run settings | Approved 2026-11-07 |

D2 to D4 affect only the grading and reporting, not the runs.

## 12. What is saved

- `llm_runs/raw_calls.jsonl`: one line per call, with the exact prompt, the raw answer, and the timings.
- `llm_runs/errors.jsonl`: calls that failed after three attempts.
- `llm_runs/run_meta.json`: Ollama version, model digests, GPU fit, settings, and the SHA-256 of every input file, per session.
- `ground_truth/nvd_truth_meta.json`: NVD data date and the SHA-256 of the Nmap dataset the truth table was built from.
