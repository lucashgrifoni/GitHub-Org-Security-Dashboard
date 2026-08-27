# Security Policy

## Supported Versions

This project is in pre-release bootstrap. Security fixes target the current
main development line until the first tagged release exists.

## Reporting a Vulnerability

Report suspected vulnerabilities privately to the project maintainer. Include
the affected version or commit, reproduction steps, and expected impact.

Do not include GitHub tokens, private repository names, organization secrets,
customer data, or sensitive audit exports in public issues.

## Data Handling

The current collector is offline-only and does not call the GitHub API. Any
future live collector must require an explicit token, use read-only scopes,
redact sensitive values, and be testable without network access.

