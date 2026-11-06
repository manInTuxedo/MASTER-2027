# Requirements and Setup

This document describes the requirements and setup for the current Docker + Nmap data-collection phase of the MASTER-2027 research project, and lists the additional tools needed for the later stages.

## 1. Supported Environment

The setup described here is based on the project author's tested environment:

- Windows desktop environment.
- Docker Desktop using the Linux container engine and WSL 2 backend.
- Docker Engine / Docker Compose CLI.
- Python 3.14 (the supplied installation log shows CPython 3.14 Windows packages).
- Nmap 7.993 (the reported successful collection run).
- PowerShell or Windows Command Prompt.
- Free disk space for roughly fifteen container images plus the OpenSSH build layers, and for the local model files (several GB in total).

Other compatible versions may work, but they have not been established by the run log described here.

## 2. Required Software

### Docker Desktop

Install Docker Desktop for Windows and ensure that its Linux engine is running.

Verify:

```
docker version
docker info
docker context ls
```

The `docker version` output should include both a **Client** section and a **Server** section. If the Server section is missing or reports an engine connection error, start or troubleshoot Docker Desktop before continuing.

The project uses the `desktop-linux` Docker context in the reported setup:

```
docker context use desktop-linux
```

### WSL 2

Docker Desktop is configured to use WSL 2 in the tested environment. Check its status with:

```
wsl --status
```

If necessary, update WSL using:

```
wsl --update
```

### Python

Install Python 3.14 or a compatible Python 3 release. Confirm that Python and pip are available:

```
python --version
python -m pip --version
```

### Nmap

Install Nmap for Windows and ensure `nmap.exe` is available on `PATH`.

Verify:

```
nmap --version
```

The collector also supports supplying the full path to `nmap.exe` through its `--nmap` argument if Nmap is not on `PATH`.

### Ollama and local models (later stages)

The model-evaluation stage uses Ollama and three small models. Install Ollama for Windows, then pull the models:

```
ollama pull llama3.2:3b
ollama pull phi4-mini
ollama pull qwen3.5:4b
ollama list
```

The `ollama list` output shows each model's ID, which will be recorded in the experiment protocol. When a model is loaded, `ollama ps` shows whether it runs on the GPU or the CPU.

## 3. Python Dependencies

### Current collector

`collect_nmap.py` uses Python standard-library modules for CSV handling, JSON serialization, XML parsing, subprocess execution, file handling, regular expressions, and timestamps. It does not require `requests`, `pandas`, or `matplotlib` to perform the current Nmap collection step.

The project author's environment also installed these packages for downstream data handling and analysis:

```
python -m pip install requests pandas matplotlib
```

Create and activate a virtual environment from the `nmap-lab` directory:

```
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install requests pandas matplotlib
```

If only the current collector is being run, the third-party package installation can be skipped. The virtual environment directory (`venv/`) should not be committed to the repository.

## 4. Repository Setup

Clone the repository:

```
git clone https://github.com/manInTuxedo/MASTER-2027.git
cd MASTER-2027
```

Move into the lab directory:

```
cd nmap-lab
```

If the repository has already been cloned, open a terminal in the existing `MASTER-2027` directory and run `cd nmap-lab`.

The lab directory is expected to contain:

```
nmap-lab/
├── docker-compose.yml
├── lab_manifest.csv
├── collect_nmap.py
└── openssh/
    └── Dockerfile
```

## 5. Start the Docker Lab

From the `nmap-lab` directory, validate the Compose configuration:

```
docker compose config
```

Download the registry images (the three OpenSSH images are built locally, not downloaded):

```
docker compose pull --ignore-buildable
```

Build the OpenSSH images from the upstream source tarballs. The first build took about five minutes in the reported run, and it needs internet access to download the OpenSSH sources:

```
docker compose build
```

Start the services in detached mode:

```
docker compose up -d
```

Check container status:

```
docker compose ps
```

The expected lab contains fifteen services and publishes these host ports on localhost:

| Service | Image | Host port | Container port |
|---|---|---|---|
| Apache old | `httpd:2.4.49` | 8001 | 80 |
| Apache mid | `httpd:2.4.54` | 8002 | 80 |
| Apache latest | `httpd:2.4.69` | 8003 | 80 |
| Nginx old | `nginx:1.18.0` | 8004 | 80 |
| Nginx mid | `nginx:1.22.1` | 8005 | 80 |
| Nginx latest | `nginx:1.30.6` | 8006 | 80 |
| MySQL old | `mysql:5.7.30` | 8007 | 3306 |
| MySQL mid | `mysql:8.0.32` | 8008 | 3306 |
| MySQL latest | `mysql:8.4.13` | 8009 | 3306 |
| Redis old | `redis:6.0.5` | 8010 | 6379 |
| Redis mid | `redis:7.0.5` | 8011 | 6379 |
| Redis latest | `redis:8.10.3` | 8012 | 6379 |
| OpenSSH old | `lab-openssh:8.4p1` | 8013 | 22 |
| OpenSSH mid | `lab-openssh:9.6p1` | 8014 | 22 |
| OpenSSH latest | `lab-openssh:10.3p1` | 8015 | 22 |

**Important:** MySQL containers can take additional time to finish initializing (roughly 20 to 40 seconds). Wait for them to become ready before scanning. Check logs if a service does not start:

```
docker compose logs
```

## 6. Run Nmap Data Collection

Ensure the Docker containers are running and Nmap is available, then run:

```
python collect_nmap.py
```

Optional arguments are supported:

```
python collect_nmap.py --manifest lab_manifest.csv --host 127.0.0.1 --out-dir results
```

If Nmap is not on `PATH`, provide its full path:

```
python collect_nmap.py --nmap "C:\Program Files (x86)\Nmap\nmap.exe"
```

The collector uses Nmap service/version detection (`-sV`) and a TCP connect scan (`-sT`) against each manifest port. For services whose manifest row names a script in the `nse_script` column (the Redis services use `redis-info`), it also runs that Nmap script so that the version is reported. It writes XML output for each service, parses the XML, records the Docker image digest if the Docker CLI is available, and exports the collected records.

Keep a previous results directory under a different name before re-running into the same output directory, because the output files are overwritten.

## 7. Expected Output Files

After a successful run, the following files should be created:

```
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
    ├── mysql_latest.xml
    ├── redis_old.xml
    ├── redis_mid.xml
    ├── redis_latest.xml
    ├── openssh_old.xml
    ├── openssh_mid.xml
    └── openssh_latest.xml
```

- `nmap_results.json`: structured dataset intended for programmatic processing and later LLM input preparation.
- `nmap_results.csv`: tabular version for inspection in spreadsheet software.
- `raw_xml/`: original Nmap XML output for each service.

The script reports the number of successfully scanned services and flags scan failures, missing version detections, or differences between expected and detected versions.

## 8. Stop the Lab

When the experiment is complete:

```
docker compose down
```

This stops and removes the Compose containers and network. It does not remove the downloaded or built images. Do not use `docker compose down -v` unless you intentionally want to remove Compose-managed volumes as well.

To reclaim disk space from the OpenSSH build cache:

```
docker builder prune
```

Stopping the lab before running the local models frees memory for them.

## 9. Troubleshooting

### Docker cannot connect to the Docker API

Example error:

```
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

Actions:

1. Start Docker Desktop.
2. Wait until its engine is running.
3. Check `docker version` and confirm that the Server section is present.
4. Select the Linux context:

```
docker context use desktop-linux
```

5. Retry:

```
docker info
```

### `docker compose pull` fails

- Confirm Docker Desktop is running.
- Check network connectivity and retry.
- Inspect the exact image/tag reported in the error.
- Confirm the image tag exists in the relevant official image repository.

### `pull access denied for lab-openssh`

This message is expected when running plain `docker compose pull`. The `lab-openssh` images are built locally, not published in a registry. Use `docker compose pull --ignore-buildable` and then `docker compose build`.

### `docker compose build` fails

- Confirm that the `openssh/` directory exists next to `docker-compose.yml` and contains the `Dockerfile`.
- The build downloads the OpenSSH source from the OpenBSD mirror, so check internet access and retry. A download error means the requested version tarball could not be fetched.
- Read the last lines of the build output; the failing step is named there.

### Nmap is not found

Check:

```
nmap --version
```

If the command is unavailable, install Nmap or pass the full executable path using `--nmap`.

### A service is not detected

Check:

```
docker compose ps
docker compose logs
```

Confirm that the relevant host port in `lab_manifest.csv` matches the Compose port mapping. Wait for MySQL initialization before scanning.

### A Redis service shows no version

Plain `-sV` identifies Redis but may not report its version. Confirm that the manifest row for that service has `redis-info` in the `nse_script` column, and that the Redis container was started with protected mode disabled (as in `docker-compose.yml`), because protected mode refuses requests that arrive through Docker's port mapping.

### Expected and detected versions differ

The images in `docker-compose.yml` are pinned to exact version tags, so a mismatch usually means a wrong tag, a banner that hides or changes the version, or a manifest typo. The exact detected version is recorded by Nmap. For reproducible experiments, record image digests, detected versions, Nmap version, and scan timestamp; the collector stores these in the dataset.

### Low disk space

Fifteen images, the OpenSSH build layers, and the local model files need several GB. Remove unused data with `docker builder prune`, and `docker image prune` if images are no longer needed.

## 10. Scope of These Requirements

The Docker/Nmap collection phase needs only the software in Sections 2 to 5. The later research stages additionally need the following.

### NVD API key

The ground-truth stage queries the NVD API. A key is free and is requested at `https://nvd.nist.gov/developers/request-an-api-key`. NVD sends a single-use activation link to the email address entered in the request. The key is shown only once, when the link is opened, and the link expires after seven days.

Store the key in an environment variable, not in a file in the repository:

```
setx NVD_API_KEY "your-key-here"
```

Open a new terminal afterwards so the variable is available. Keys should not be shared or committed to the repository. Without a key, the public rate limit is much lower, so key-less runs are slower.

### Other stages

- Scripts for prompt execution, repeated trials, automated CVE grading, baseline comparison, and metric calculation.
- An experiment protocol that fixes the prompts, JSON output format, model settings, and metric definitions before any model is evaluated.

Those components should be documented with their exact versions and configuration when they are implemented. They are not prerequisites for running `collect_nmap.py` as it currently exists.