# Five-minute demo

1. **Show the application (one minute).** Sign in, create a finding, choose a severity, and resolve it. State that these are manual findings, not imported scan output.
2. **Show isolation (one minute).** Sign in as another account in a private browser window. The first user's findings should be absent. Open `tests/test_security.py` and point to the cross-user write rejection test.
3. **Explain controls (one minute).** Walk through parameterized SQL, template escaping, and the before-request CSRF check. Explain why SameSite cookies alone are not the only CSRF defense.
4. **Show pipeline evidence (one minute).** Once GitHub has actually run it, show the five prerequisite jobs, downloaded scanner reports, and the aggregate release gate. Until then describe these as configured, not successfully executed.
5. **Discuss a tradeoff (one minute).** ZAP sees the unauthenticated login page; application tests check authenticated logic. A public deployment would need TLS, centralized throttling, and better identity management.

## Questions to be ready for

**Why both SAST and DAST?** Source scanning identifies suspicious code patterns without running the app. ZAP observes HTTP behavior. Neither proves the absence of vulnerabilities.

**Why scan dependencies and the container?** The pinned Python dependency list and the final image cover different components. The image includes OS packages and its actual installed library versions.

**What stops a failed scan from shipping?** The release job checks the result of every required job. Only all-success results allow downloading and republishing the already-scanned image. The pipeline does not rebuild a different image at release time.

**Does a failed workflow block merges?** Only if the repository ruleset requires the release-gate status check. The YAML itself gates the release artifact.

**How do sessions get revoked?** The cookie contains an account ID and version. Every authenticated request compares that version to SQLite. Logout increments the database version and clears the cookie, invalidating all that account's earlier sessions.

**What would you improve next?** Authenticated DAST, action SHA / image digest pinning, rule vendoring, edge rate limiting, password reset and MFA, and a genuine deployment environment with rollback.

## Accurate resume wording

Use after you have personally run and reviewed the project:

> Implemented a Flask/SQLite security-finding tracker with account-level access controls, CSRF protection, scrypt password hashing, and automated security regression tests.

> Configured a GitHub Actions pipeline integrating Semgrep, Gitleaks, Trivy, and OWASP ZAP, with an aggregate gate controlling publication of a scanned container artifact.

Only after a successful GitHub run and the failure exercise:

> Validated security gates through a controlled failing pull request and successful container-artifact release, retaining scanner reports as CI evidence.

Use the actual completion date. Do not claim production deployment, measured vulnerability reductions, earlier completion, or successful scans without supporting evidence. This implementation covers the DevSecOps project concept; it does not substantiate every historical claim in an existing resume.
