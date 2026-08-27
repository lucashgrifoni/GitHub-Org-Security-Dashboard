# Security Policy

## Supported Versions

This project is in pre-release bootstrap. Security fixes target the current
main development line until the first tagged release exists.

## Reporting a Vulnerability

Report privately through GitHub's private vulnerability reporting, which is
enabled on this repository: open the Security tab and choose "Report a
vulnerability". The report is visible only to the maintainer until a fix is
published, so no detail reaches a public issue while the problem is live.

Include the affected version or commit, reproduction steps, and expected
impact. A minimal fixture that triggers the behaviour is the most useful thing
you can attach, since the tool is offline and takes its input from a local
file.

Do not include GitHub tokens, private repository names, organization secrets,
customer data, or sensitive audit exports in public issues.

## Data Handling

The current collector is offline-only and does not call the GitHub API. Any
future live collector must require an explicit token, use read-only scopes,
redact sensitive values, and be testable without network access.

