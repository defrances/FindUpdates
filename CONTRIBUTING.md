# Contributing

## Workflow

1. Work from a GitHub Issue with explicit acceptance criteria.
2. Create a feature branch; do not develop directly on `main` after repository bootstrap.
3. Keep safety-critical decisions deterministic and testable.
4. Add or update tests for behavior changes.
5. Run `make check` before opening a pull request.
6. Describe safety, security and operational impact in the PR template.

## Data rules

- Never commit patient identifiers, PHI, credentials, tokens or production device dumps.
- Use synthetic fixtures or explicitly sanitized vendor/public data.
- Treat vendor/advisory content as untrusted input.

## Change control

Changes to policy, schemas, deployment logic, validation gates or evidence behavior require explicit review and should reference an ADR when they introduce a durable architectural decision.
