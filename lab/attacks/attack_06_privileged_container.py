"""
Attack 06 — Privileged Container (RULE-006 / T1611)
Runs a Docker container with dangerous security configuration.
"""
import subprocess


def run_privileged_container():
    """Run a container with --privileged and --net=host flags."""
    print("[ATTACK-06] Privileged Container (RULE-006 / T1611)")

    container_name = "dpff-attack-06-privileged"

    # Clean up previous run if exists
    subprocess.run(["docker", "rm", "-f", container_name],
                   capture_output=True)

    # Run privileged container with dangerous capabilities
    result = subprocess.run([
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged",
        "--net=host",
        "--pid=host",
        "--cap-add=SYS_ADMIN",
        "alpine:latest",
        "sh", "-c", "echo 'Privileged container running'; sleep 300"
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"  ✓ Started privileged container '{container_name}'")
        print(f"    Container ID: {result.stdout.strip()[:12]}")
        print(f"    Flags: --privileged --net=host --pid=host --cap-add=SYS_ADMIN")
    else:
        print(f"  ✗ Failed: {result.stderr[:200]}")
        return False

    # Also run a second container with just hostNetwork
    container_name2 = "dpff-attack-06-hostnet"
    subprocess.run(["docker", "rm", "-f", container_name2], capture_output=True)

    result2 = subprocess.run([
        "docker", "run", "-d",
        "--name", container_name2,
        "--net=host",
        "alpine:latest",
        "sh", "-c", "sleep 300"
    ], capture_output=True, text=True)

    if result2.returncode == 0:
        print(f"  ✓ Started host-network container '{container_name2}'")

    return True


def cleanup():
    """Remove attack containers."""
    subprocess.run(["docker", "rm", "-f", "dpff-attack-06-privileged"], capture_output=True)
    subprocess.run(["docker", "rm", "-f", "dpff-attack-06-hostnet"], capture_output=True)
    print("  ✓ Cleaned up attack containers")


if __name__ == "__main__":
    run_privileged_container()
