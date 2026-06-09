"""
Shared configuration and helpers for all attack scripts.
"""
import os
import time
import requests

# ── Lab service URLs ──────────────────────────────────────────
GITEA_URL = os.getenv("GITEA_URL", "http://localhost:3000")
JENKINS_URL = os.getenv("JENKINS_URL", "http://localhost:9090")
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:5000")

# ── Gitea admin credentials (created by seed_project.py) ──────
GITEA_USER = "dpff-admin"
GITEA_PASS = "dpff-lab-2024"
GITEA_ORG = "dpff-lab"
GITEA_REPO = "sample-app"

# ── Jenkins credentials ──────────────────────────────────────
JENKINS_USER = "admin"
JENKINS_TOKEN = ""  # Set after Jenkins first boot

# ── Helpers ───────────────────────────────────────────────────

def gitea_api(method, endpoint, **kwargs):
    """Make an authenticated Gitea API call."""
    url = f"{GITEA_URL}/api/v1{endpoint}"
    kwargs.setdefault("auth", (GITEA_USER, GITEA_PASS))
    kwargs.setdefault("headers", {"Content-Type": "application/json"})
    resp = requests.request(method, url, **kwargs)
    return resp


def _get_jenkins_crumb():
    """Fetch Jenkins CSRF crumb for POST requests."""
    try:
        resp = requests.get(
            f"{JENKINS_URL}/crumbIssuer/api/json",
            auth=(JENKINS_USER, JENKINS_TOKEN),
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {data['crumbRequestField']: data['crumb']}
    except Exception:
        pass
    return {}


def jenkins_api(method, endpoint, **kwargs):
    """Make an authenticated Jenkins API call with CSRF crumb."""
    url = f"{JENKINS_URL}{endpoint}"
    kwargs.setdefault("auth", (JENKINS_USER, JENKINS_TOKEN))

    # For POST/PUT, add CSRF crumb header
    if method.upper() in ("POST", "PUT", "DELETE"):
        crumb = _get_jenkins_crumb()
        if crumb:
            headers = kwargs.get("headers", {}) or {}
            headers.update(crumb)
            kwargs["headers"] = headers

    resp = requests.request(method, url, **kwargs)
    return resp


def wait_for_service(url, name, timeout=120):
    """Wait until a service responds to HTTP requests."""
    print(f"  Waiting for {name} at {url}...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                print(f" ready ({time.time()-start:.0f}s)")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(2)
        print(".", end="", flush=True)
    print(f" TIMEOUT after {timeout}s!")
    return False


def wait_for_all_services():
    """Wait for Gitea, Jenkins, and Registry to be ready."""
    print("\n=== Waiting for Lab Services ===")
    ok = True
    ok &= wait_for_service(f"{GITEA_URL}/api/v1/version", "Gitea")
    ok &= wait_for_service(f"{JENKINS_URL}/api/json", "Jenkins", timeout=180)
    ok &= wait_for_service(f"{REGISTRY_URL}/v2/", "Registry")
    if ok:
        print("All services ready!\n")
    else:
        print("WARNING: Some services failed to start.\n")
    return ok
