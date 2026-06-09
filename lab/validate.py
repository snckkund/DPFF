"""
DPFF Lab Validator
Runs DPFF analysis against the lab, then checks that all 7 rules are detected.
"""
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Load lab environment variables BEFORE importing DPFF modules
from dotenv import load_dotenv

lab_env = os.path.join(os.path.dirname(__file__), '.env.lab')
if os.path.exists(lab_env):
    load_dotenv(lab_env, override=True)
    print(f"  Loaded env from {lab_env}")

# Set Gitea auth from lab defaults if not already set
os.environ.setdefault('GITEA_USER', 'dpff-admin')
os.environ.setdefault('GITEA_PASS', 'dpff-lab-2024')
os.environ.setdefault('JENKINS_USER', 'admin')
os.environ.setdefault('JENKINS_TOKEN', 'admin')

from src.main import run_analysis, analyze_events
from src.integrity import hash_events, verify_all, generate_chain_of_custody
from src.database import ForensicDatabase
from src.reporters.timeline import TimelineReporter
from src.reporters.json_export import JsonExporter
from src.reporters.stix_export import StixExporter
from src.reporters.html import HtmlReporter
import yaml
import time


# Expected detection rules
EXPECTED_RULES = {
    "RULE-001": "Pipeline Injection",
    "RULE-002": "Credential Theft",
    "RULE-003": "Dependency Confusion",
    "RULE-004": "Artifact Tampering",
    "RULE-005": "Obfuscated Command",
    "RULE-006": "Privileged Container",
    "RULE-007": "Multi-Stage Attack",
}


def load_lab_config():
    """Load the lab YAML config."""
    config_path = os.path.join(project_root, "config_lab.yaml")
    if not os.path.exists(config_path):
        print(f"ERROR: Lab config not found at {config_path}")
        sys.exit(1)

    with open(config_path, 'r') as f:
        return yaml.safe_load(f), config_path


def run_validation():
    """Run DPFF against the lab and validate detections."""
    print("=" * 60)
    print("  DPFF Lab Validator — Running Analysis")
    print("=" * 60)

    config, config_path = load_lab_config()
    start_time = time.time()

    # Create args-like object for run_analysis
    class Args:
        pass
    args = Args()
    args.config = config_path

    events = run_analysis(args, config_override=config)

    if not events:
        print("\n  WARNING: No events collected!")
        print("  Check that lab services are running and attacks have been executed.")
        return False

    # Correlate events
    print(f"\n  Collected {len(events)} events. Correlating...")
    findings = analyze_events(events)
    duration = time.time() - start_time

    # Verify integrity
    integrity = verify_all(events)
    custody = generate_chain_of_custody(events) if events else {}

    # Save to database
    db = ForensicDatabase()
    investigation_id = db.save_investigation(
        mode="lab-analysis",
        events=events,
        findings=findings,
        root_hash=custody.get('root_hash', ''),
        duration_seconds=duration
    )

    # Generate reports
    output_dir = os.path.join(project_root, "lab", "reports")
    os.makedirs(output_dir, exist_ok=True)

    HtmlReporter(os.path.join(output_dir, "lab_report.html")).generate(findings)
    TimelineReporter(os.path.join(output_dir, "lab_timeline.html")).generate(events, findings)
    JsonExporter(os.path.join(output_dir, "lab_export.json")).export(
        events=events, findings=findings,
        investigation_id=investigation_id, mode="lab-analysis",
        duration=duration, integrity=integrity, custody=custody,
    )
    StixExporter(os.path.join(output_dir, "lab_export_stix.json")).export(
        events=events, findings=findings,
        investigation_id=investigation_id,
    )

    # ── Validation ────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  Validation Results")
    print(f"{'=' * 60}")
    print(f"  Investigation ID : {investigation_id}")
    print(f"  Events Collected : {len(events)}")
    print(f"  Findings         : {len(findings)}")
    print(f"  Integrity        : {'INTACT' if integrity['integrity_intact'] else 'COMPROMISED'}")
    print(f"  Duration         : {duration:.2f}s")

    # Check which rules were detected
    detected_rules = set()
    for f in findings:
        if hasattr(f, 'rule_id') and f.rule_id:
            detected_rules.add(f.rule_id)

    print(f"\n  {'Rule':<12} {'Expected':<25} {'Detected':<10}")
    print(f"  {'─'*12} {'─'*25} {'─'*10}")

    all_passed = True
    for rule_id, description in EXPECTED_RULES.items():
        detected = rule_id in detected_rules
        status = "✓" if detected else "✗ MISS"
        if not detected:
            all_passed = False
        print(f"  {rule_id:<12} {description:<25} {status}")

    # Check for false positives (unexpected rules)
    unexpected = detected_rules - set(EXPECTED_RULES.keys())
    if unexpected:
        print(f"\n  ⚠ Unexpected rules detected: {unexpected}")

    # Final verdict
    print(f"\n{'=' * 60}")
    if all_passed:
        print("  ✅ PASSED — All 7 rules detected, zero false negatives!")
    else:
        missing = set(EXPECTED_RULES.keys()) - detected_rules
        print(f"  ❌ FAILED — Missing detections: {missing}")
    print(f"  Reports saved to: {output_dir}")
    print(f"{'=' * 60}")

    return all_passed


if __name__ == "__main__":
    success = run_validation()
    sys.exit(0 if success else 1)
