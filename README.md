# Project Description

## Project Title

**Can Small Local LLMs Map Nmap Results to CVEs Without Hallucinating? An Empirical Evaluation**

## 1. Overview

This repository contains the experimental environment for a cybersecurity research study investigating whether small language models (LLMs) running locally can reliably interpret Nmap service-detection results and suggest relevant Common Vulnerabilities and Exposures (CVEs).

The central research concern is not only whether a model can identify vulnerabilities, but whether its claims are trustworthy. In particular, the study distinguishes between:

- **Correct CVE:** the CVE exists and applies to the detected product and version.
- **Real but wrong CVE:** the CVE exists, but does not apply to the detected product/version.
- **Fabricated CVE:** the cited CVE identifier does not exist.
- **Missing CVE:** a relevant known vulnerability is not identified by the model.

The lab is designed to produce repeatable service/version observations that can later be supplied to local LLMs and compared against a ground-truth dataset derived from the National Vulnerability Database (NVD).

## 2. Current Implementation Status

The currently implemented phases are the **Docker-based service lab and Nmap data-collection pipeline** (dataset v2, 15 services) and the **first build of the NVD ground-truth table** (2026-11-06).

The lab defines fifteen services: five product families, each represented by an older, intermediate, and latest version.

| Product family | Lab role | Docker image | Host port |
|---|---|---|---|
| Apache HTTP Server | Old | `httpd:2.4.49` | 8001 |
| Apache HTTP Server | Mid | `httpd:2.4.54` | 8002 |
| Apache HTTP Server | Latest | `httpd:2.4.69` | 8003 |
| Nginx | Old | `nginx:1.18.0` | 8004 |
| Nginx | Mid | `nginx:1.22.1` | 8005 |
| Nginx | Latest | `nginx:1.30.6` | 8006 |
| MySQL | Old | `mysql:5.7.30` | 8007 |
| MySQL | Mid | `mysql:8.0.32` | 8008 |
| MySQL | Latest | `mysql:8.4.13` | 8009 |
| Redis | Old | `redis:6.0.5` | 8010 |
| Redis | Mid | `redis:7.0.5` | 8011 |
| Redis | Latest | `redis:8.10.3` | 8012 |
| OpenSSH | Old | `lab-openssh:8.4p1` (built locally) | 8013 |
| OpenSSH | Mid | `lab-openssh:9.6p1` (built locally) | 8014 |
| OpenSSH | Latest | `lab-openssh:10.3p1` (built locally) | 8015 |

The `old`, `mid`, and `latest` labels are experimental group labels. They do not, by themselves, establish that an image is vulnerable or secure. Applicability must be checked against authoritative vulnerability data and the exact detected product/version.

The `latest` images were first run with mutable tags (`httpd:2.4`, `nginx:stable`, `mysql:8.4`, `redis:8`) and then pinned to the exact versions that Nmap detected in that run.

### Recorded Nmap run (dataset v2)

In the reported run (2026-11-05, Nmap 7.993), Nmap detected all fifteen services and reported:

| Service | Detected version |
|---|---|
| Apache old / mid / latest | 2.4.49 / 2.4.54 / 2.4.69 |
| Nginx old / mid / latest | 1.18.0 / 1.22.1 / 1.30.6 |
| MySQL old / mid / latest | 5.7.30 / 8.0.32 / 8.4.13 |
| Redis old / mid / latest | 6.0.5 / 7.0.5 / 8.10.3 |
| OpenSSH old / mid / latest | 8.4 / 9.6 / 10.3 |

These are observations from the run described by the project author. For reproducibility, the dataset records the Nmap version, scan command, scan timestamp, and a Docker image digest for each service (see `image_digest`).

### NVD ground-truth table (first build, 2026-11-06)

`build_nvd_truth.py` queried the NVD CVE API for each of the fifteen detected product/versions. NVD data was retrieved on 2026-11-06 (NVD response timestamp 20:21 UTC). The table was built from the `nmap_results.json` file with SHA-256 `7b4f4909c5857eeac06f01ddaca4a75eb7a732f1bec740fc6ccebac66e2f8b13`, and contains 508 (service, CVE) rows. The number of applicable CVEs per service, and how many of them are found when Nmap's CPE is used exactly as printed (the unmodified baseline lookup), are:

| Product | Old: truth / raw CPE | Mid: truth / raw CPE | Latest: truth / raw CPE |
|---|---|---|---|
| Apache HTTP Server | 88 / 88 | 72 / 72 | 0 / 0 |
| Nginx | 6 / 0 | 2 / 0 | 0 / 0 |
| MySQL | 81 / 0 | 118 / 0 | 0 / 0 |
| Redis | 29 / 29 | 21 / 21 | 0 / 0 |
| OpenSSH | 37 / 37 | 31 / 31 | 23 / 23 |

Observations:

- For nginx and MySQL, a lookup that uses Nmap's CPE unchanged returns nothing, because NVD records these products under different vendor names (`f5:nginx` and `oracle:mysql`). The ground truth therefore queries each service under every known alias and merges the results; the `found_by` column records which name found each CVE.
- The latest Apache, nginx, MySQL, and Redis versions have no applicable CVEs in NVD at the query date, so they act as clean controls for this date only.
- Three sanity checks on well-known CVEs (Apache 2.4.49, nginx 1.18.0, OpenSSH 9.6) were found as expected.
- **Under review:** for all three OpenSSH versions, three CVEs (CVE-2007-2768, CVE-2008-3844, CVE-2023-51767) were found by the primary query method but not by the cross-check method. The latest OpenSSH version also has 23 applicable CVEs, so it is not a clean control. The truth table therefore includes two review columns: `cve_tags` (for example `disputed`) and `unbounded_version_match` (NVD attaches the CVE to the product with no version limits). How these entries are counted will be fixed in the experiment protocol.

Notes on specific products:

- **Redis.** In preliminary testing with Nmap 7.94, plain service detection (`-sV`) identified the service as Redis but did not report a version. The Redis versions in this dataset were obtained by also running Nmap's own `redis-info` script. The manifest column `nse_script` records which services use an additional script.
- **OpenSSH.** There is no official OpenSSH image with selectable versions, so the three images are built from the upstream source tarballs (`nmap-lab/openssh/Dockerfile`). Distribution packages can carry security fixes without changing the reported version number, which would make NVD-based ground truth unreliable. The banner of an upstream source build reports the version without the portable suffix (for example `8.4` rather than `8.4p1`), so the manifest's expected versions are `8.4`, `9.6`, and `10.3`.
- **Image digests.** For images pulled from a registry, `image_digest` holds the registry digest. For the locally built OpenSSH images it holds the local image ID.

## 3. System Architecture

The current pipeline is:

1. **Docker Compose lab:** starts the fifteen isolated service containers (twelve pulled images and three locally built OpenSSH images).
2. **Lab manifest:** defines each service identifier, product family, experimental role, image, expected version, published host port, and an optional Nmap script name.
3. **Nmap service detection:** the Python collector invokes Nmap against each published localhost port using service/version detection (`-sV`) and a TCP connect scan, adding a product-specific Nmap script only where the manifest specifies one.
4. **XML collection:** Nmap writes its native XML output for each service.
5. **Data transformation:** Python parses the XML, extracts service details and CPE values, and converts legacy CPE 2.2 values to CPE 2.3 (including the NVD convention of storing the OpenSSH `p1` suffix as the CPE update field).
6. **Image digest recording:** if the Docker CLI is available, the collector records the image digest for each service.
7. **Dataset export:** structured records are written to JSON and CSV for inspection and downstream experiments.

The NVD ground-truth stage is a separate script (`build_nvd_truth.py`). It reads `nmap_results.json`, queries the NVD CVE API (primary method `cpeName` with `isVulnerable`, cross-check with `virtualMatchString`), queries each service under known vendor aliases, caches every raw reply, and writes the truth table together with metadata (query date, SHA-256 of the Nmap dataset, settings).

Nmap is used here for host-port and service/version discovery. Nmap service detection does **not** independently prove that a service is vulnerable and does not itself provide the study's final CVE ground truth.

## 4. Repository Components

| Component | Purpose |
|---|---|
| `nmap-lab/docker-compose.yml` | Defines the fifteen Docker services and localhost port mappings. |
| `nmap-lab/openssh/Dockerfile` | Builds an upstream OpenSSH release from source for a requested version. |
| `nmap-lab/lab_manifest.csv` | Experimental manifest describing the services, intended versions, ports, and optional Nmap scripts. |
| `nmap-lab/collect_nmap.py` | Runs Nmap, parses XML, prepares structured records, records image digests, and exports datasets. |
| `nmap-lab/results/nmap_results.json` | Main structured Nmap dataset. |
| `nmap-lab/results/nmap_results.csv` | Flat dataset suitable for spreadsheet inspection. |
| `nmap-lab/results/raw_xml/` | Raw per-service Nmap XML evidence. |
| `nmap-lab/build_nvd_truth.py` | Queries NVD for each service, merges vendor aliases, and builds the ground-truth table. |
| `nmap-lab/ground_truth/nvd_truth.csv` | Ground truth: one row per (service, CVE), with CVSS, NVD status, tags, and which query found it. |
| `nmap-lab/ground_truth/nvd_truth_summary.csv` | Per-service counts, method used, and review notes. |
| `nmap-lab/ground_truth/nvd_crosscheck_differences.csv` | CVEs on which the two NVD query methods disagree. |
| `nmap-lab/ground_truth/nvd_truth_meta.json` | Query date, Nmap dataset SHA-256, settings, and sanity checks. |
| `nmap-lab/ground_truth/nvd_raw/` | Raw NVD replies kept as evidence and used as a cache. |

The collector also records useful metadata such as the Nmap version, scan command, scan time, elapsed time, detected service/version, CPE values (including a primary CPE 2.3 value for NVD lookup), image digest, a model-input text field, and whether a detected version matches the manifest's expected version.

## 5. Research Workflow (Planned)

The broader research experiment is intended to proceed as follows:

1. Build and validate a ground-truth list of applicable CVEs for each tested product/version using NVD data, and record the date and time of the query together with a hash of the Nmap dataset it was built from. *(First build implemented on 2026-11-06; review of the OpenSSH entries is in progress.)*
2. Provide the Nmap-derived service observations to three locally hosted small LLMs served through Ollama: `llama3.2:3b`, `phi4-mini`, and `qwen3.5:4b`. Model digests will be recorded in the experiment protocol.
3. Evaluate multiple prompt conditions:
   - Direct CVE identification request.
   - The same request with an explicit instruction to abstain rather than invent identifiers.
   - A constrained prompt that asks the model to select only from a supplied NVD-derived candidate list.
4. Run each condition once at temperature 0 and three times at temperature 0.7 to measure output stability. With 15 services, 3 prompts, 3 models, and 4 runs, this gives 540 answers, each of which may cite several CVEs.
5. Validate every model-proposed CVE against NVD and product/version applicability.
6. Compare model performance with a non-LLM baseline based on CPE identification and NVD lookup.
7. Calculate and report the evaluation metrics.
8. Optionally, test incomplete input: for example, Redis scanned without the `redis-info` script so that no version is reported, to examine how models handle missing information.

The prompts, JSON output format, model settings, and metric definitions will be fixed in an experiment protocol before any model is evaluated.

The Docker/Nmap collection stage and the first build of the NVD ground-truth table are implemented as described above. The experiment protocol, local-LLM evaluation, automated grading, and baseline comparison should be treated as subsequent research stages unless separately implemented and documented in the repository.

## 6. Evaluation Metrics

The planned evaluation includes:

- **Precision:** proportion of model-reported CVEs that are applicable and correct.
- **Recall:** proportion of ground-truth applicable CVEs that the model identifies.
- **Fabricated-CVE rate:** proportion of cited CVEs that do not exist.
- **Real-but-wrong rate:** proportion of cited CVEs that exist but do not apply to the scanned product/version.
- **Abstention rate:** proportion of model responses in which the model explicitly declines to make a claim or reports uncertainty.
- **Stability:** consistency of outputs across repeated runs of the same experimental condition.
- **Response time:** time required to produce a response.

Some CVEs exist in NVD but have no applicability data (for example, entries that are still awaiting analysis), so they cannot be judged applicable or inapplicable. These are planned to be reported as a separate category rather than counted as real-but-wrong.

Ground-truth sizes range from 0 to 118 CVEs per service. For services with an empty truth set, precision and recall are undefined, so only rates that do not depend on the truth set (for example fabricated-CVE rate and abstention rate) apply to them.

Metric definitions and denominators should be fixed in the experiment protocol before evaluating models, and reported separately where categories overlap or differ.

## 7. Safety and Ethical Scope

The Docker services are published on `127.0.0.1` so that the lab ports are bound to the local machine rather than exposed on the LAN by the Compose configuration. The experiment should be limited to systems owned by the researcher or systems for which explicit authorization has been obtained.

The MySQL password in the Compose file is a fake, lab-only credential. It must not be reused in real environments. The Redis containers run with protected mode disabled, which is acceptable only because their ports are bound to localhost in this lab. The OpenSSH images contain a host key generated at build time and do not allow password login; they are for lab use only.

## 8. Current Data Outputs

After running the collector from the `nmap-lab` directory, the expected outputs are:

```
nmap-lab/
└── results/
    ├── nmap_results.json
    ├── nmap_results.csv
    └── raw_xml/
        ├── apache_old.xml
        ├── apache_mid.xml
        ├── apache_latest.xml
        ├── nginx_old.xml
        ├── nginx_mid.xml
        ├── nginx_latest.xml
        ├── mysql_old.xml
        ├── mysql_mid.xml
        ├── mysql_latest.xml
        ├── redis_old.xml
        ├── redis_mid.xml
        ├── redis_latest.xml
        ├── openssh_old.xml
        ├── openssh_mid.xml
        └── openssh_latest.xml
```

After running `build_nvd_truth.py`, the ground-truth outputs are:

```
nmap-lab/
└── ground_truth/
    ├── nvd_truth.csv
    ├── nvd_truth_summary.csv
    ├── nvd_crosscheck_differences.csv
    ├── nvd_truth_meta.json
    └── nvd_raw/
```

The JSON file is the primary structured dataset. The CSV file is a convenient tabular representation. The raw XML files preserve the original Nmap output and should be retained as experimental evidence.

## 9. Known Limitations

- **Scope of the dataset.** Five product families on one host, scanned through Docker port mappings. Results may not generalize to other products or network conditions.
- **Vendor naming differences.** The CPE names that Nmap reports do not always match the names NVD uses. For example, Nmap reports MySQL under `mysql:mysql` while NVD records Oracle MySQL under `oracle:mysql`, and Nmap reports nginx under `igor_sysoev:nginx` while NVD also uses `f5:nginx`. A baseline that uses Nmap's CPE unchanged may therefore miss CVEs, and the ground-truth construction has to account for these aliases.
- **Version granularity.** The OpenSSH banner does not include the portable `p1` suffix, and some products report only the version string the service chooses to expose.
- **Group labels.** `latest` services may still have CVEs recorded in NVD. NVD data, not the group label, defines the ground truth.
- **NVD changes over time.** NVD records are updated continuously, so the ground truth is valid for the recorded query date. Recently published CVEs may not yet have applicability data, so a clean result for a very recent version reflects NVD at that date.
- **All-versions entries.** Some NVD entries attach a CVE to a product without any version limits (some are tagged as disputed). They match every version, including very new ones, and are flagged in the truth table rather than silently removed.
- **Unequal truth-set sizes.** Services range from 0 to 118 applicable CVEs, which affects how recall can be interpreted across services.

## 10. Data Sources

Ground-truth vulnerability data will come from the National Vulnerability Database. This product uses the NVD API but is not endorsed or certified by the NVD.

## 11. Research Principle

The system treats LLM output as **unverified candidate information**, not as authoritative vulnerability evidence. A CVE claim is counted as correct only after checking both that the CVE exists and that its affected-product/version criteria apply to the service under evaluation.