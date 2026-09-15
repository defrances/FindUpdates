# Security policy

FindUpdates is an early development project and is not approved for production medical-device deployment.

## Reporting a vulnerability

Do not disclose exploitable security issues, credentials, patient information or sensitive device details in a public Issue. Use GitHub's private vulnerability reporting/security-advisory mechanism when available, or contact the repository owner privately through GitHub.

## Security expectations

- No long-lived production credentials in source control or CI logs.
- No PHI or patient identifiers in repository data, fixtures, AI prompts or logs.
- External advisories are untrusted input.
- AI output cannot authorize deployment or override deterministic policy gates.
- Deployment access must follow least privilege and environment approval controls.
