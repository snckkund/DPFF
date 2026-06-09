"""
Run All Attacks — Master Orchestrator
Executes all 7 attack scenarios against the lab infrastructure in sequence.
"""
import time
import sys

from config import wait_for_all_services

# Import all attack modules
from attack_01_pipeline_injection import create_malicious_job
from attack_02_credential_theft import push_malicious_commit
from attack_03_dependency_confusion import inject_dependency_confusion
from attack_04_artifact_tampering import tamper_artifact
from attack_05_obfuscated_command import create_obfuscated_job
from attack_06_privileged_container import run_privileged_container
from attack_07_multistage_chain import execute_attack_chain


ATTACKS = [
    ("01", "Pipeline Injection",     "RULE-001", "T1059.004", create_malicious_job),
    ("02", "Credential Theft",       "RULE-002", "T1078",     push_malicious_commit),
    ("03", "Dependency Confusion",   "RULE-003", "T1195.002", inject_dependency_confusion),
    ("04", "Artifact Tampering",     "RULE-004", "T1525",     tamper_artifact),
    ("05", "Obfuscated Command",     "RULE-005", "T1027",     create_obfuscated_job),
    ("06", "Privileged Container",   "RULE-006", "T1611",     run_privileged_container),
    ("07", "Multi-Stage Chain",      "RULE-007", "T1195",     execute_attack_chain),
]


def main():
    print("=" * 60)
    print("  DPFF Attack Lab — Running All Attacks")
    print("=" * 60)
    print()

    # Verify services
    if not wait_for_all_services():
        print("ERROR: Lab services not ready. Run `docker compose up -d` first.")
        sys.exit(1)

    results = []

    for num, name, rule, mitre, attack_fn in ATTACKS:
        print(f"\n{'─' * 60}")
        try:
            success = attack_fn()
            results.append((num, name, rule, mitre, "✓" if success else "✗"))
        except Exception as e:
            print(f"  ✗ Exception: {e}")
            results.append((num, name, rule, mitre, "✗"))
        time.sleep(2)  # Brief pause between attacks

    # Summary
    print(f"\n{'=' * 60}")
    print("  Attack Execution Summary")
    print(f"{'=' * 60}")
    print(f"  {'#':<4} {'Attack':<25} {'Rule':<12} {'MITRE':<12} {'Status':<6}")
    print(f"  {'─'*4} {'─'*25} {'─'*12} {'─'*12} {'─'*6}")

    for num, name, rule, mitre, status in results:
        print(f"  {num:<4} {name:<25} {rule:<12} {mitre:<12} {status}")

    passed = sum(1 for r in results if r[4] == "✓")
    print(f"\n  Result: {passed}/7 attacks executed successfully")
    print(f"{'=' * 60}")

    print("\n  Next step: Run DPFF analysis against the lab:")
    print("    python src/main.py analyze --config config_lab.yaml")
    print("  Or run the validator:")
    print("    python lab/validate.py")


if __name__ == "__main__":
    main()
