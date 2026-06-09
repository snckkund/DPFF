"""
Attack 02 — Credential Theft (RULE-002 / T1078)
Pushes a commit from a suspicious author modifying sensitive files.
Uses the existing admin account but sets the commit author to 'attacker'.
"""
import base64
from config import GITEA_ORG, GITEA_REPO, gitea_api


def push_malicious_commit():
    """Push a commit with attacker author that modifies .env file."""
    print("[ATTACK-02] Credential Theft (RULE-002 / T1078)")

    # We commit as the admin user but set the author metadata to 'attacker'
    # This simulates stolen credentials being used by a malicious actor
    env_content = base64.b64encode(
        b"# Stolen credentials\nAWS_SECRET_KEY=AKIA1234567890EXAMPLE\nDB_PASSWORD=production-secret-123\n"
    ).decode()

    # Check if .env exists
    get_resp = gitea_api("GET", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/.env")

    if get_resp.status_code == 200:
        sha = get_resp.json().get("sha", "")
        resp = gitea_api("PUT", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/.env",
            json={
                "message": "Update environment config",
                "content": env_content,
                "sha": sha,
                "author": {"name": "attacker", "email": "attacker@evil.com"},
                "committer": {"name": "attacker", "email": "attacker@evil.com"},
            })
    else:
        resp = gitea_api("POST", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/.env",
            json={
                "message": "Add environment config",
                "content": env_content,
                "author": {"name": "attacker", "email": "attacker@evil.com"},
                "committer": {"name": "attacker", "email": "attacker@evil.com"},
            })

    if resp.status_code in (200, 201):
        print("  ✓ Pushed malicious .env commit as 'attacker'")
    else:
        print(f"  ✗ Failed to push commit: {resp.status_code}: {resp.text[:200]}")
        return False

    # Also modify .ssh/id_rsa (sensitive file pattern for correlator)
    ssh_content = base64.b64encode(
        b"-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATA1234567890\n-----END RSA PRIVATE KEY-----\n"
    ).decode()

    resp2 = gitea_api("POST", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/credentials/id_rsa",
        json={
            "message": "Add deployment key",
            "content": ssh_content,
            "author": {"name": "attacker", "email": "attacker@evil.com"},
            "committer": {"name": "attacker", "email": "attacker@evil.com"},
        })

    if resp2.status_code in (200, 201):
        print("  ✓ Pushed credentials/id_rsa as 'attacker'")
    elif resp2.status_code == 422:
        print("  ✓ credentials/id_rsa already exists")

    return True


if __name__ == "__main__":
    push_malicious_commit()
