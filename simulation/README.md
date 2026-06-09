# Simulation Artifacts

This directory contains the ground-truth data generated from the 4 simulated attack scenarios.

## Attack 1: Pipeline Injection
- `malicious_ci.yml`: The compromised GitHub Actions workflow.
- `runner_logs.txt`: Simulated logs showing credential exfiltration.

## Attack 2: Credential Theft & Backdoor
- `app_backdoored.js`: The application code with the injected backdoor.
- `git_log.txt`: The Git history showing the unauthorized commit.

## Attack 3: Dependency Confusion
- `package_malicious.json`: The manifest requesting the public malicious package.
- `npm_install_log.txt`: Logs confirmation the malicious package was installed.

## Attack 4: Artifact Tampering
- `registry_audit.json`: Harbor logs showing the image digest change between CI push and Deployment pull.
