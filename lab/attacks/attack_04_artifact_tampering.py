"""
Attack 04 — Artifact Tampering (RULE-004 / T1525)
Pushes an image to the registry, then re-tags with different content (digest mismatch).
"""
import subprocess
import requests
from config import REGISTRY_URL


def get_digest(repo, tag):
    """Get the Docker-Content-Digest for an image:tag from the registry."""
    # Use HEAD request with proper accept header
    resp = requests.head(
        f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.headers.get("Docker-Content-Digest", "")

    # Fallback: try GET
    resp = requests.get(
        f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.headers.get("Docker-Content-Digest", "")

    return ""


def tamper_artifact():
    """Push a legitimate image, then re-push with modified content under same tag."""
    print("[ATTACK-04] Artifact Tampering (RULE-004 / T1525)")

    image = "localhost:5000/dpff-sample-app"
    repo = "dpff-sample-app"
    tag = "release-1.0"

    # Step 1: Create a legitimate image
    print("  → Building legitimate image...")
    result = subprocess.run(
        ["docker", "build", "-t", f"{image}:{tag}", "--no-cache", "-f-", "."],
        input="FROM alpine:latest\nRUN echo 'legitimate build v1' > /version.txt\n",
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ✗ Build failed: {result.stderr[:200]}")
        return False

    # Step 2: Push the legitimate image
    print("  → Pushing legitimate image...")
    result = subprocess.run(["docker", "push", f"{image}:{tag}"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ✗ Push failed: {result.stderr[:200]}")
        return False
    print(f"  ✓ Pushed legitimate {image}:{tag}")

    # Step 3: Get the original digest
    original_digest = get_digest(repo, tag)
    print(f"  → Original digest: {original_digest[:40] if original_digest else 'N/A'}...")

    # Step 4: Build a DIFFERENT image with the SAME tag (tampering)
    print("  → Building tampered image (same tag, different content)...")
    subprocess.run(
        ["docker", "build", "-t", f"{image}:{tag}", "--no-cache", "-f-", "."],
        input="FROM alpine:latest\nRUN echo 'TAMPERED by attacker' > /version.txt\nRUN echo 'backdoor installed' > /tmp/payload\n",
        capture_output=True, text=True,
    )

    # Step 5: Push the tampered image under the same tag
    print("  → Pushing tampered image over legitimate tag...")
    result = subprocess.run(["docker", "push", f"{image}:{tag}"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ✗ Tampered push failed: {result.stderr[:200]}")
        return False

    # Step 6: Verify digest changed
    new_digest = get_digest(repo, tag)
    print(f"  → New digest: {new_digest[:40] if new_digest else 'N/A'}...")

    if original_digest and new_digest and original_digest != new_digest:
        print(f"  ✓ Artifact tampered! Digest changed.")
    elif not original_digest or not new_digest:
        print(f"  ⚠ Could not verify digests from registry (push still happened)")
    else:
        print("  ⚠ Digests match — build cache may have been used")

    return True


if __name__ == "__main__":
    tamper_artifact()
