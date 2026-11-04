# Requirements and Setup

This document describes the requirements and setup for the current
Docker + Nmap data-collection phase of the MASTER-2027 research project.

## 1. Supported Environment

The setup described here is based on the project author's tested
environment:

-   Windows desktop environment.
-   Docker Desktop using the Linux container engine and WSL 2 backend.
-   Docker Engine / Docker Compose CLI.
-   Python 3.14 (the supplied installation log shows CPython 3.14
    Windows packages).
-   Nmap 7.993 (the reported successful collection run).
-   PowerShell or Windows Command Prompt.

Other compatible versions may work, but they have not been established
by the run log described here.

## 2. Required Software

### Docker Desktop

Install Docker Desktop for Windows and ensure that its Linux engine is
running.

Verify:

``` powershell
docker version
docker info
docker context ls
```

The `docker version` output should include both a **Client** section and
a **Server** section. If the Server section is missing or reports an
engine connection error, start or troubleshoot Docker Desktop before
continuing.

The project uses the `desktop-linux` Docker context in the reported
setup:

``` powershell
docker context use desktop-linux
```

### WSL 2

Docker Desktop is configured to use WSL 2 in the tested environment.
Check its status with:

``` powershell
wsl --status
```

If necessary, update WSL using:

``` powershell
wsl --update
```

### Python

Install Python 3.14 or a compatible Python 3 release. Confirm that
Python and pip are available:

``` powershell
python --version
python -m pip --version
```

### Nmap

Install Nmap for Windows and ensure `nmap.exe` is available on `PATH`.

Verify:

``` powershell
nmap --version
```

The collector also supports supplying the full path to `nmap.exe`
through its `--nmap` argument if Nmap is not on `PATH`.

## 3. Python Dependencies

### Current collector

`collect_nmap.py` uses Python standard-library modules for CSV handling,
JSON serialization, XML parsing, subprocess execution, file handling,
regular expressions, and timestamps. It does not require `requests`,
`pandas`, or `matplotlib` to perform the current Nmap collection step.

The project author's environment also installed these packages for
possible downstream data handling and analysis:

``` powershell
python -m pip install requests pandas matplotlib
```

Create and activate a virtual environment from the `nmap-lab` directory:

``` powershell
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install requests pandas matplotlib
```

If only the current collector is being run, the third-party package
installation can be skipped.

## 4. Repository Setup

Clone the repository:

``` powershell
git clone https://github.com/manInTuxedo/MASTER-2027.git
cd MASTER-2027
```

Move into the lab directory:

``` powershell
cd nmap-lab
```

If the repository has already been cloned, open a terminal in the
existing `MASTER-2027` directory and run `cd nmap-lab`.

## 5. Start the Docker Lab

From the `nmap-lab` directory, validate the Compose configuration:

``` powershell
docker compose config
```

Download the images:

``` powershell
docker compose pull
```

Start the services in detached mode:

``` powershell
docker compose up -d
```

Check container status:

``` powershell
docker compose ps
```

The expected lab contains nine services and publishes these host ports
on localhost:

  Service           Host port   Container port
  --------------- ----------- ----------------
  Apache old             8001               80
  Apache mid             8002               80
  Apache latest          8003               80
  Nginx old              8004               80
  Nginx mid              8005               80
  Nginx latest           8006               80
  MySQL old              8007             3306
  MySQL mid              8008             3306
  MySQL latest           8009             3306

**Important:** MySQL containers can take additional time to finish
initializing. Wait for them to become ready before scanning. Check logs
if a service does not start:

``` powershell
docker compose logs
```

## 6. Run Nmap Data Collection

Ensure the Docker containers are running and Nmap is available, then
run:

``` powershell
python collect_nmap.py
```

Optional arguments are supported:

``` powershell
python collect_nmap.py --manifest lab_manifest.csv --host 127.0.0.1 --out-dir results
```

If Nmap is not on `PATH`, provide its full path:

``` powershell
python collect_nmap.py --nmap "C:\Program Files (x86)\Nmap\nmap.exe"
```

The collector uses Nmap service/version detection (`-sV`) and a TCP
connect scan (`-sT`) against each manifest port. It writes XML output
for each service, parses the XML, and exports the collected records.

## 7. Expected Output Files

After a successful run, the following files should be created:

``` text
results/
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

-   `nmap_results.json`: structured dataset intended for programmatic
    processing and later LLM input preparation.
-   `nmap_results.csv`: tabular version for inspection in spreadsheet
    software.
-   `raw_xml/`: original Nmap XML output for each service.

The script reports the number of successfully scanned services and flags
scan failures, missing version detections, or differences between
expected and detected versions.

## 8. Stop the Lab

When the experiment is complete:

``` powershell
docker compose down
```

This stops and removes the Compose containers and network. It does not
remove the downloaded images. Do not use `docker compose down -v` unless
you intentionally want to remove Compose-managed volumes as well.

## 9. Troubleshooting

### Docker cannot connect to the Docker API

Example error:

``` text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

Actions:

1.  Start Docker Desktop.
2.  Wait until its engine is running.
3.  Check `docker version` and confirm that the Server section is
    present.
4.  Select the Linux context:

``` powershell
docker context use desktop-linux
```

5.  Retry:

``` powershell
docker info
```

### `docker compose pull` fails

-   Confirm Docker Desktop is running.
-   Check network connectivity and retry.
-   Inspect the exact image/tag reported in the error.
-   Confirm the image tag exists in the relevant official image
    repository.

### Nmap is not found

Check:

``` powershell
nmap --version
```

If the command is unavailable, install Nmap or pass the full executable
path using `--nmap`.

### A service is not detected

Check:

``` powershell
docker compose ps
docker compose logs
```

Confirm that the relevant host port in `lab_manifest.csv` matches the
Compose port mapping. Wait for MySQL initialization before scanning.

### Expected and detected versions differ

The `latest` image tags (`httpd:2.4`, `nginx:stable`, and `mysql:8.4`)
can resolve to newer versions over time. The exact detected version is
recorded by Nmap. For reproducible experiments, record image digests,
detected versions, Nmap version, and scan timestamp; consider pinning
image digests for later repeated experiments.

## 10. Scope of These Requirements

These instructions cover the implemented Docker/Nmap collection phase.
The broader research plan may additionally require:

-   Ollama and selected local LLM model files.
-   NVD API access and a ground-truth preparation/validation process.
-   Scripts for prompt execution, repeated trials, automated CVE
    grading, baseline comparison, and metric calculation.

Those components should be documented with their exact versions and
configuration when they are implemented. They are not prerequisites for
running `collect_nmap.py` as it currently exists.
