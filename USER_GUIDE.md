# User Guide - DevSecOps Pipeline Forensics Framework (DPFF)

This guide explains how to install, configure, and use DPFF to investigate security incidents in your CI/CD pipelines.

## 1. Prerequisites
- **Python 3.9+** installed.
- **Docker** (optional, for container logs).
- Access to your CI/CD tools (GitHub, Jenkins, Harbor, Kubernetes).

## 2. Installation
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/dpff.git
    cd dpff
    ```
2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 3. Configuration
Control the behavior of the framework using `config.yaml`.

### 3.1. Enable Collectors
Edit `config.yaml` to enable or disable specific data sources:

```yaml
collector_settings:
  github:
    enabled: true
    org: "my-org"
  
  jenkins:
    enabled: true
    url: "http://jenkins.local:8080"
    
  kubernetes:
    enabled: true
```

### 3.2. Set Credentials
Set the following environment variables to allow the tool to fetch logs:

- **GitHub**: `GITHUB_TOKEN` (Personal Access Token)
- **Jenkins**: `JENKINS_USER`, `JENKINS_TOKEN`
- **Harbor**: `HARBOR_USER`, `HARBOR_PASS`

On Windows (PowerShell):
```powershell
$env:GITHUB_TOKEN = "your_token_here"
```

## 4. Running the Tool

### Mode A: Simulation (Test Drive)
Run the verification suite to see the framework detect known attacks in the sample data.

```bash
python src/main.py simulate
```
**Output**: 4 reports generated automatically (see Section 6).

### Mode B: Analysis (Live Investigation)
Run the tool against your configured environment.

```bash
python src/main.py analyze --config config.yaml
```

### Mode C: Investigation History
View all past investigations stored in the SQLite database.

```bash
python src/main.py history
```

### Web Dashboard (Streamlit)
Launch the web-based forensic dashboard:

```bash
streamlit run dashboard.py
```
Features: KPI metrics, severity-coded incidents with MITRE ATT&CK IDs and confidence scores, evidence drilldown with hashes, integrity status, chain-of-custody viewer, investigation history tab, and **download buttons for Timeline, JSON, and STIX exports**.

### Desktop App (Tkinter)
Launch the standalone desktop application:

```bash
python desktop_app.py
```
Features: Investigation mode selector, configuration panel for live analysis, incident tree with Rule ID / Severity / MITRE ID / Confidence columns, evidence drilldown with SHA-256 hashes, integrity indicator, auto-generated exports, and investigation history.

## 5. Interpreting the Report

### HTML Report (`forensic_report.html`)
- **Severity Badges**: Each incident has a severity level (CRITICAL, HIGH, MEDIUM, LOW) displayed as a colored badge.
- **Evidence Timeline**: A chronological list of correlated events (Commit → Build → Push → Deploy) related to that incident.
- **Evidence Hashes**: Each piece of evidence has a SHA-256 hash that can be used to verify it hasn't been tampered with.

### Interactive Timeline (`forensic_timeline.html`)
An interactive dark-themed visualization that allows you to:
- Filter events: **All** / **Malicious** / **Benign**
- Click sidebar findings to **highlight and scroll** to related events
- Click any event for a **detail panel** with source, hash, MITRE ID, and confidence

## 6. Forensic Outputs

After each investigation, DPFF automatically generates:

| Output | Location | Purpose |
|---|---|---|
| HTML Report | `forensic_report.html` | Visual incident report with severity badges |
| Interactive Timeline | `forensic_timeline.html` | Filterable event timeline with incident highlighting |
| JSON Export | `forensic_export.json` | Structured forensic data with integrity/custody info |
| STIX 2.1 Bundle | `forensic_export_stix.json` | Threat intelligence exchange (Identity, Indicator, Attack-Pattern, Relationship, Report) |
| Log File | `logs/dpff.log` | Full audit trail (rotated at 5MB) |
| Database | `data/dpff.db` | Persistent storage of all investigations |
| Chain of Custody | (in-memory / dashboard) | Evidence manifest with root hash |

## 7. Detection Rules

| Rule | Detection | MITRE ATT&CK | Severity |
|---|---|---|---|
| RULE-001 | Pipeline Injection / Data Exfiltration (curl, wget, nc) | T1059.004 | CRITICAL |
| RULE-002 | Credential Theft / Unauthorized Access (flagged authors, .env mods) | T1078 | HIGH |
| RULE-003 | Dependency Confusion / Supply Chain (abnormal versions, public registry) | T1195.002 | CRITICAL |
| RULE-004 | Artifact Tampering (unauthorized pushers, digest mismatch) | T1525 | CRITICAL |
| RULE-005 | Obfuscated Commands (base64, eval, PowerShell encoded) | T1027 | HIGH |
| RULE-006 | Privileged Containers (privileged: true, hostNetwork, CAP_SYS_ADMIN) | T1611 | CRITICAL |
| RULE-007 | Multi-Stage Attack Chain (cross-event correlation in 30-min window) | T1195 | CRITICAL |

Each finding includes:
- **Confidence Score** (0–100%): Higher when more indicators match
- **MITRE ATT&CK ID**: Maps to the relevant technique
- **Rule ID**: Unique identifier for the detection rule

## 8. Collector Error Handling

All collectors use the `BaseCollector._safe_request()` method which provides:
- **3 retries** with exponential backoff (1s, 2s, 4s)
- **30s default timeout** per request
- **Rate-limit** handling (HTTP 429 with `Retry-After`)
- **Graceful degradation**: returns partial results if some API calls fail
- **Specific exception handling**: ConnectionError, Timeout, HTTPError (4xx vs 5xx)

## 9. Testing

```bash
python -m pytest tests/ -v
```

80 tests in 5 files covering:
- **test_correlator.py** (30): All 7 detection rules — positive detection and false-positive avoidance
- **test_collectors.py** (14): Config validation, retry logic, rate-limit handling, collection stats
- **test_exports.py** (16): JSON structure, STIX 2.1 bundle validity, confidence scaling
- **test_integrity.py** (12): SHA-256 hashing and chain of custody
- **test_database.py** (11): SQLite persistence and investigation history
