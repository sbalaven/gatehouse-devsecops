# Validation record

Checked locally on **2026-09-20**, using Python 3.12 on Windows.

| Check | Result |
| --- | --- |
| Install Flask, Waitress and their pinned runtime dependencies | Passed |
| `python -m unittest discover -s tests -v` | **22 tests passed**, 63.860 seconds |
| Parse workflow, Dependabot, Compose and Semgrep YAML | Passed; syntax parsing only |
| Real HTTP browser demo with Waitress and headless Edge | Passed: login, three findings, resolve, logout |
| Desktop screenshot, 1440 px viewport | Captured and visually reviewed |
| Mobile browser check, 390 px viewport | Passed; no page overflow or JavaScript errors |
| Docker build / Compose / image startup | **Not run: Docker unavailable locally** |
| Semgrep, Gitleaks, Trivy and ZAP execution | **Not run: configured for GitHub Actions** |
| GitHub Actions end-to-end workflow | Published to GitHub; first workflow triggered. Final scanner results not yet verified. |
| Branch ruleset / required status check | **Not configured: requires repository settings** |
| Controlled failing pull request | **Not run: exercise instructions included** |
| Cloud / production deployment | **Not implemented** |

## Test coverage

The suite checks health, anonymous access, account creation and password hashing, finding lifecycle, invalid credentials, login and write CSRF enforcement, token rotation, logout cookie replay, cross-account read/write isolation, SQL-injection-shaped usernames, escaped HTML, invalid fields, oversized requests, account lockout and expiry, response headers, cookie flags, invalid hosts, mutation HTTP methods, missing secrets, weak passwords, and duplicate accounts.

Testing found and fixed an invalid-host error-rendering crash and SQLite test connections that remained open during Windows temporary-directory cleanup. Browser validation found and fixed a mobile grid overflow.

Passing these tests is not evidence that scanners have passed or that the app is production-ready. Run the actual workflow, inspect its reports, and update this file with run links and dates. Do not replace failures with claimed successes.

## Publication check

Published at https://github.com/sbalaven/gatehouse-devsecops. A fresh download was compared byte-for-byte with the 25-file local release; all files matched. The first security workflow was observed queued/running after publication. Consult Actions for current results.
