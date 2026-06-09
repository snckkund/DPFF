"""
Seed the lab: create Gitea user, org, repo, and push the sample app.
Run this once after `docker compose up -d`.
"""
import base64
import requests
from config import (
    GITEA_URL, GITEA_USER, GITEA_PASS, GITEA_ORG, GITEA_REPO,
    wait_for_all_services, gitea_api
)


def create_user():
    """Create the admin user in Gitea."""
    print("[1/4] Creating Gitea admin user...")
    # Use Gitea's built-in admin creation endpoint
    resp = requests.post(f"{GITEA_URL}/api/v1/admin/users", json={
        "username": GITEA_USER,
        "password": GITEA_PASS,
        "email": f"{GITEA_USER}@dpff-lab.local",
        "must_change_password": False,
        "login_name": GITEA_USER,
        "source_id": 0,
    }, auth=(GITEA_USER, GITEA_PASS))

    if resp.status_code == 201:
        print(f"  ✓ User '{GITEA_USER}' created")
    elif resp.status_code == 422:
        print(f"  ✓ User '{GITEA_USER}' already exists")
    else:
        # Try registering via public registration
        resp2 = requests.post(f"{GITEA_URL}/user/sign_up", data={
            "user_name": GITEA_USER,
            "email": f"{GITEA_USER}@dpff-lab.local",
            "password": GITEA_PASS,
            "retype": GITEA_PASS,
        })
        if resp2.status_code in (200, 302):
            print(f"  ✓ User '{GITEA_USER}' registered via sign-up")
        else:
            print(f"  ✗ Failed to create user: {resp.status_code} / {resp2.status_code}")
            return False
    return True


def create_org():
    """Create the dpff-lab organization."""
    print("[2/4] Creating organization...")
    resp = gitea_api("POST", "/orgs", json={
        "username": GITEA_ORG,
        "full_name": "DPFF Attack Lab",
        "visibility": "public",
    })
    if resp.status_code == 201:
        print(f"  ✓ Organization '{GITEA_ORG}' created")
    elif resp.status_code == 422:
        print(f"  ✓ Organization '{GITEA_ORG}' already exists")
    else:
        print(f"  ✗ Org creation returned {resp.status_code}: {resp.text[:200]}")
    return True


def create_repo():
    """Create the sample-app repository under the organization."""
    print("[3/4] Creating repository...")
    resp = gitea_api("POST", f"/orgs/{GITEA_ORG}/repos", json={
        "name": GITEA_REPO,
        "description": "Sample CI/CD app for DPFF forensic testing",
        "private": False,
        "auto_init": True,  # Creates initial commit with README
    })
    if resp.status_code == 201:
        print(f"  ✓ Repository '{GITEA_ORG}/{GITEA_REPO}' created")
    elif resp.status_code == 409:
        print(f"  ✓ Repository '{GITEA_ORG}/{GITEA_REPO}' already exists")
    else:
        print(f"  ✗ Repo creation returned {resp.status_code}: {resp.text[:200]}")
    return True


def push_sample_app():
    """Push sample app files to the repository via Gitea API."""
    print("[4/4] Pushing sample app files...")

    import os
    sample_dir = os.path.join(os.path.dirname(__file__), '..', 'sample-app')

    files_to_push = {
        'app.js': 'app.js',
        'package.json': 'package.json',
        'Dockerfile': 'Dockerfile',
        'Jenkinsfile': 'Jenkinsfile',
    }

    for filename, repo_path in files_to_push.items():
        filepath = os.path.join(sample_dir, filename)
        if not os.path.exists(filepath):
            print(f"  ✗ File not found: {filepath}")
            continue

        with open(filepath, 'r') as f:
            content = base64.b64encode(f.read().encode()).decode()

        # Try creating the file (will fail if exists)
        resp = gitea_api("POST", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/{repo_path}", json={
            "message": f"Add {filename}",
            "content": content,
        })

        if resp.status_code == 201:
            print(f"  ✓ Pushed {filename}")
        elif resp.status_code == 422:
            # File exists — update it
            # First get the SHA
            get_resp = gitea_api("GET", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/{repo_path}")
            if get_resp.status_code == 200:
                sha = get_resp.json().get("sha", "")
                resp2 = gitea_api("PUT", f"/repos/{GITEA_ORG}/{GITEA_REPO}/contents/{repo_path}", json={
                    "message": f"Update {filename}",
                    "content": content,
                    "sha": sha,
                })
                if resp2.status_code == 200:
                    print(f"  ✓ Updated {filename}")
                else:
                    print(f"  ✗ Failed to update {filename}: {resp2.status_code}")
            else:
                print(f"  ✗ File exists but couldn't get SHA: {get_resp.status_code}")
        else:
            print(f"  ✗ Failed to push {filename}: {resp.status_code}: {resp.text[:200]}")


def main():
    print("=" * 60)
    print("  DPFF Attack Lab — Project Seeding")
    print("=" * 60)

    if not wait_for_all_services():
        print("Services not ready. Aborting.")
        return

    create_user()
    create_org()
    create_repo()
    push_sample_app()

    print("\n" + "=" * 60)
    print("  Seeding complete!")
    print(f"  Gitea: {GITEA_URL}/{GITEA_ORG}/{GITEA_REPO}")
    print("=" * 60)


if __name__ == "__main__":
    main()
