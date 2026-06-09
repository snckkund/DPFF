# DevSecOps Pipeline Forensics Framework (DPFF)

DPFF is a forensic readiness and investigation framework designed for CI/CD environments. It allows security teams to detect, investigate, and correlate supply chain attacks across the entire pipeline (SCM, CI, Artifact Registry, Cluster).

## Key Features

- **Evidence Collection** — Automated log collection from GitHub, Jenkins, Harbor, Kubernetes, and Docker with retry/backoff, rate-limit handling, and graceful degradation
- **Correlation Engine** — 7 pattern-based detection rules with regex matching, confidence scoring (0–100%), and MITRE ATT&CK mapping
- **Evidence Integrity** — SHA-256 hashing of all collected evidence with chain-of-custody manifests
- **Structured Logging** — Full audit trail in `logs/dpff.log` with rotating file handler
- **Data Persistence** — SQLite database (`data/dpff.db`) stores all investigations for future reference
- **Multiple UIs** — CLI, Streamlit dashboard (with export downloads), and Tkinter desktop app
- **Export Formats** — HTML report, interactive timeline, JSON forensic export, and STIX 2.1 bundle

## Detection Rules

| Rule | Detection | MITRE ATT&CK | Severity |
|---|---|---|---|
| RULE-001 | Pipeline Injection / Data Exfiltration | T1059.004 | CRITICAL |
| RULE-002 | Credential Theft / Unauthorized Access | T1078 | HIGH |
| RULE-003 | Dependency Confusion / Supply Chain | T1195.002 | CRITICAL |
| RULE-004 | Artifact Tampering | T1525 | CRITICAL |
| RULE-005 | Obfuscated Commands | T1027 | HIGH |
| RULE-006 | Privileged Containers | T1611 | CRITICAL |
| RULE-007 | Multi-Stage Attack Chain (cross-event) | T1195 | CRITICAL |

## Project Structure

- `src/`: Source code for the forensic framework
    - `collectors/`: Evidence collectors with retry/backoff (GitHub, Jenkins, Harbor, K8s, Docker)
    - `correlation_engine/`: 7 regex-based detection rules with MITRE mapping
    - `reporters/`: HTML report, interactive timeline, JSON export, STIX 2.1 export
    - `integrity.py`: SHA-256 evidence hashing and chain-of-custody
    - `database.py`: SQLite persistence layer
    - `forensic_logger.py`: Centralized structured logging
    - `main.py`: CLI entry point for the forensic tool
- `simulation/`: Generated "Ground Truth" data representing 4 attack scenarios
- `tests/`: 80 unit tests (correlator, collectors, exports, integrity, database)
- `scripts/`: Utilities for audit log collection
- `infra/`: Infrastructure-as-Code for the forensic lab

## Getting Started

> [!TIP]
> For a comprehensive walkthrough of installation, configuration, and usage, please see the **[User Guide](USER_GUIDE.md)**.

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (optional, for lab environment)

### Installation

1.  Clone the repository.
2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Usage

The framework supports three CLI modes:

**1. Simulation Mode (Demo)**
```bash
python src/main.py simulate
```

**2. Analysis Mode (Real Data)**
```bash
python src/main.py analyze --config config.yaml
```

**3. Investigation History**
```bash
python src/main.py history
```

**4. Dashboard (Web UI)**
```bash
streamlit run dashboard.py
```

**5. Desktop App (GUI)**

```bash
# Python (development)
python desktop_app.py

# Packaged executable (no Python required)
dist\DPFF\DPFF.exe
```

The Tkinter desktop app provides a fully self-contained forensic workstation:

| Tab | Description |
|---|---|
| 📈 Dashboard | Live KPI cards (events, incidents, critical alerts, integrity) + severity bar chart |
| 🚨 Incidents | Sortable incident table — click any row to view full evidence timeline |
| 🕐 Timeline | Visual event timeline scrollable by time |
| 📄 Report | In-app HTML report viewer |

**Quickstart (lab)**

1. Start the lab: `cd lab && docker compose up -d`
2. Launch `dist\DPFF\DPFF.exe`
3. Set **Mode → Analyze** — the config panel opens with lab defaults pre-filled
4. Click **▶ Run Investigation**
5. Watch per-collector status in the **Activity Log** (bottom-right); the progress bar shows in the toolbar
6. Switch to **Incidents** and click any row to see the evidence detail

**Settings** are automatically saved to `~/.dpff/settings.json` on close (credentials, theme, mode, report path).

**Report output** — click 📂 next to the Report filename field to choose a custom save location (`~/Documents/DPFF/` by default).

Each investigation automatically:
- Hashes all evidence with SHA-256
- Verifies evidence integrity
- Generates a chain-of-custody manifest
- Saves results to `data/dpff.db`
- Outputs 4 reports: `forensic_report.html`, `forensic_timeline.html`, `forensic_export.json`, `forensic_export_stix.json`

## Testing

```bash
python -m pytest tests/ -v
```

80 tests covering: detection rules (30), collector error handling (14), export formats (16), evidence integrity (12), database (11).

## Production Status

See [docs/production_readiness.md](docs/production_readiness.md) for a detailed assessment of the current state and roadmap to production.
