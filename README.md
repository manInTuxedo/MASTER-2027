# Project Description

## Project Title

**Can Small Local LLMs Map Nmap Results to CVEs Without Hallucinating?
An Empirical Evaluation**

## 1. Overview

This repository contains the experimental environment for a
cybersecurity research study investigating whether small language models
(LLMs) running locally can reliably interpret Nmap service-detection
results and suggest relevant Common Vulnerabilities and Exposures
(CVEs).

The central research concern is not only whether a model can identify
vulnerabilities, but whether its claims are trustworthy. In particular,
the study distinguishes between:

-   **Correct CVE:** the CVE exists and applies to the detected product
    and version.
-   **Real but wrong CVE:** the CVE exists, but does not apply to the
    detected product/version.
-   **Fabricated CVE:** the cited CVE identifier does not exist.
-   **Missing CVE:** a relevant known vulnerability is not identified by
    the model.

The lab is designed to produce repeatable service/version observations
that can later be supplied to local LLMs and compared against a
ground-truth dataset derived from the National Vulnerability Database
(NVD).

## 2. Current Implementation Status

The current implemented phase is the **Docker-based service lab and Nmap
data-collection pipeline**.

The lab currently defines nine services: three product families, each
represented by an older, intermediate, and latest image tag.

  Product family       Lab role   Docker image       Host port
  -------------------- ---------- ---------------- -----------
  Apache HTTP Server   Old        `httpd:2.4.49`          8001
  Apache HTTP Server   Mid        `httpd:2.4.54`          8002
  Apache HTTP Server   Latest     `httpd:2.4`             8003
  Nginx                Old        `nginx:1.18.0`          8004
  Nginx                Mid        `nginx:1.22.1`          8005
  Nginx                Latest     `nginx:stable`          8006
  MySQL                Old        `mysql:5.7.30`          8007
  MySQL                Mid        `mysql:8.0.32`          8008
  MySQL                Latest     `mysql:8.4`             8009

The `old`, `mid`, and `latest` labels are experimental group labels.
They do not, by themselves, establish that an image is vulnerable or
secure. Applicability must be checked against authoritative
vulnerability data and the exact detected product/version.

### Recorded Nmap run

In the reported successful run, Nmap detected all nine services and
reported:

  Service         Detected version
  --------------- ------------------
  Apache old      2.4.49
  Apache mid      2.4.54
  Apache latest   2.4.69
  Nginx old       1.18.0
  Nginx mid       1.22.1
  Nginx latest    1.30.6
  MySQL old       5.7.30
  MySQL mid       8.0.32
  MySQL latest    8.4.13

These are observations from the run described by the project author, not
a guarantee that mutable image tags such as `stable` or `2.4` will
resolve to the same versions in future runs. Record image digests and
scan timestamps when strict reproducibility is required.

## 3. System Architecture

The current pipeline is:

1.  **Docker Compose lab:** starts the nine isolated service containers.
2.  **Lab manifest:** defines each service identifier, product family,
    experimental role, image, expected version, and published host port.
3.  **Nmap service detection:** the Python collector invokes Nmap
    against each published localhost port using service/version
    detection.
4.  **XML collection:** Nmap writes its native XML output for each
    service.
5.  **Data transformation:** Python parses the XML, extracts service
    details and CPE values, and converts legacy CPE 2.2 values to CPE
    2.3 where possible.
6.  **Dataset export:** structured records are written to JSON and CSV
    for inspection and downstream experiments.

Nmap is used here for host-port and service/version discovery. Nmap
service detection does **not** independently prove that a service is
vulnerable and does not itself provide the study's final CVE ground
truth.

## 4. Repository Components

  --------------------------------------------------------------------------
  Component                              Purpose
  -------------------------------------- -----------------------------------
  `nmap-lab/docker-compose.yml`          Defines the nine Docker services
                                         and localhost port mappings.

  `nmap-lab/lab_manifest.csv`            Experimental manifest describing
                                         the services and intended versions.

  `nmap-lab/collect_nmap.py`             Runs Nmap, parses XML, prepares
                                         structured records, and exports
                                         datasets.

  `nmap-lab/results/nmap_results.json`   Main structured Nmap dataset.

  `nmap-lab/results/nmap_results.csv`    Flat dataset suitable for
                                         spreadsheet inspection.

  `nmap-lab/results/raw_xml/`            Raw per-service Nmap XML evidence.
  --------------------------------------------------------------------------

The collector also records useful metadata such as the Nmap version,
scan command, scan time, elapsed time, detected service/version, CPE
values, a model-input text field, and whether a detected version matches
the manifest's expected version.

## 5. Research Workflow (Planned)

The broader research experiment is intended to proceed as follows:

1.  Build and validate a ground-truth list of applicable CVEs for each
    tested product/version using NVD data.
2.  Provide the Nmap-derived service observations to two or three
    locally hosted small LLMs.
3.  Evaluate multiple prompt conditions:
    -   Direct CVE identification request.
    -   The same request with an explicit instruction to abstain rather
        than invent identifiers.
    -   A constrained prompt that asks the model to select only from a
        supplied NVD-derived candidate list.
4.  Repeat model queries to measure output stability.
5.  Validate every model-proposed CVE against NVD and product/version
    applicability.
6.  Compare model performance with a non-LLM baseline based on CPE
    identification and NVD lookup.
7.  Calculate and report the evaluation metrics.

The Docker/Nmap collection stage is implemented as described above. The
local-LLM evaluation, NVD ground-truth construction, automated grading,
and baseline comparison should be treated as subsequent research stages
unless separately implemented and documented in the repository.

## 6. Evaluation Metrics

The planned evaluation includes:

-   **Precision:** proportion of model-reported CVEs that are applicable
    and correct.
-   **Recall:** proportion of ground-truth applicable CVEs that the
    model identifies.
-   **Fabricated-CVE rate:** proportion of cited CVEs that do not exist.
-   **Real-but-wrong rate:** proportion of cited CVEs that exist but do
    not apply to the scanned product/version.
-   **Abstention rate:** proportion of model responses in which the
    model explicitly declines to make a claim or reports uncertainty.
-   **Stability:** consistency of outputs across repeated runs of the
    same experimental condition.
-   **Response time:** time required to produce a response.

Metric definitions and denominators should be fixed in the experiment
protocol before evaluating models, and reported separately where
categories overlap or differ.

## 7. Safety and Ethical Scope

The Docker services are published on `127.0.0.1` so that the lab ports
are bound to the local machine rather than exposed on the LAN by the
Compose configuration. The experiment should be limited to systems owned
by the researcher or systems for which explicit authorization has been
obtained.

The MySQL password in the Compose file is a fake, lab-only credential.
It must not be reused in real environments.

## 8. Current Data Outputs

After running the collector from the `nmap-lab` directory, the expected
outputs are:

``` text
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
        └── mysql_latest.xml
```

The JSON file is the primary structured dataset. The CSV file is a
convenient tabular representation. The raw XML files preserve the
original Nmap output and should be retained as experimental evidence.

## 9. Research Principle

The system treats LLM output as **unverified candidate information**,
not as authoritative vulnerability evidence. A CVE claim is counted as
correct only after checking both that the CVE exists and that its
affected-product/version criteria apply to the service under evaluation.
