# Threat model

## Scope

A local portfolio app serving browser users through Waitress. Assets: password hashes, signed session cookies, session signing key, account-owned findings, and the release artifact. Boundaries: browser → application; application → SQLite; pull-request code → read-only CI token; scan results → release gate.

| Threat | Control | Residual risk |
| --- | --- | --- |
| Reading or changing another user's findings | Server derives owner from authenticated session; every query includes owner | No organizational roles or sharing model |
| SQL injection | Bound query parameters | Future query changes must preserve this pattern |
| Stored XSS | Jinja autoescaping; restrictive CSP; no inline scripts | Rich HTML content is intentionally unsupported |
| CSRF on login or mutations | Random session-bound token; POST-only mutation routes; SameSite=Lax | XSS could defeat token protections |
| Password theft from database | Werkzeug scrypt with per-password salt | Weak user-chosen passwords can still be guessed offline |
| Online password guessing | Five failures → five-minute account lock | Account denial of service; no global/IP throttling |
| Stolen session replay after logout | Version checked in DB; logout increments it | Cookie replay remains possible before logout/expiry |
| Malicious Host header | Explicit trusted hosts | Public hostname configuration must be maintained |
| Leaked repository secrets | Gitleaks history scan; ignored local state | Detection patterns are incomplete; rotate any real exposure |
| Vulnerable release | Dependency/image gates; aggregate gate; export same scanned image | Scanners have false negatives; mutable tools and feeds |
| CI privilege misuse | Read-only contents permission; no persisted checkout credentials; no deploy keys | Third-party actions and scanner images remain supply-chain dependencies |

No production exposure was tested. ZAP performs a passive unauthenticated baseline only. Local HTTP is for loopback demonstrations; production TLS termination, backups, monitoring, abuse controls, and secret management are outside this implementation.
