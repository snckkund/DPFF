"""
Attack 07 — Multi-Stage Attack Chain (RULE-007 / T1195)
Executes attacks 01 + 02 + 04 in rapid sequence to trigger cross-event correlation.
The correlator flags this when multiple sources show compromise within 30 minutes.
"""
import time
from attack_01_pipeline_injection import create_malicious_job
from attack_02_credential_theft import push_malicious_commit
from attack_04_artifact_tampering import tamper_artifact


def execute_attack_chain():
    """Execute a coordinated multi-stage supply chain attack."""
    print("[ATTACK-07] Multi-Stage Attack Chain (RULE-007 / T1195)")
    print("  → Executing coordinated attacks within 30-min correlation window...")
    print()

    # Stage 1: Inject code via malicious commit (SCM compromise)
    print("  ── Stage 1: SCM Compromise ──")
    push_malicious_commit()
    time.sleep(2)

    # Stage 2: Pipeline injection via CI (build compromise)
    print()
    print("  ── Stage 2: CI Compromise ──")
    create_malicious_job()
    time.sleep(2)

    # Stage 3: Tamper with built artifact (artifact compromise)
    print()
    print("  ── Stage 3: Artifact Compromise ──")
    tamper_artifact()

    print()
    print("  ✓ Multi-stage attack chain complete!")
    print("  ✓ All 3 stages executed within correlation window")
    return True


if __name__ == "__main__":
    execute_attack_chain()
