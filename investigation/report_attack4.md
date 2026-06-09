# Forensic Investigation Report: Case #004 - Artifact Tampering

**Date:** 2026-02-05
**Investigator:** DPFF Automated Agent
**Incident Type:** Post-Build Artifact Modification
**Severity:** CRITICAL

## Executive Summary
A discrepancy was detected between the container image built by the CI system and the image deployed to production. Analysis of registry audit logs confirms unauthorized modification of the image tag `library/myapp:build-101`.

## Evidence Analyzed
1.  **File:** `registry_audit.json` (Harbor Audit Logs)

## Findings
### 1. Timeline Anomaly
Audit logs show the following sequence:

*   **14:26:40 (1738768000)**: User `jenkins-ci` pushed `library/myapp:build-101`. Digest: `sha256:abcd...` (Legitimate)
*   **14:28:20 (1738768100)**: User `attacker` pushed `library/myapp:build-101`. Digest: `sha256:bad1...` (Malicious)

### 2. Deployment of Compromised Image
*   **14:28:40 (1738768120)**: User `kubernetes-deployer` pulled `library/myapp:build-101`. Digest: `sha256:bad1...`

The deployment system pulled the image pushed by `attacker`, not the one built by `jenkins-ci`.

## Root Cause
- **Mutable Image Tags:** The tag `build-101` was overwritten. 
- **Registry Permissions:** User `attacker` had write access to the registry.
- **Lack of Admission Control:** Deployment did not verify the image signature or digest against the CI output.

## Recommendations
1.  Enable Content Trust / Image Signing (Notary).
2.  Use immutable image tags.
3.  Deploy by digest (`image@sha256:...`) instead of tag.
