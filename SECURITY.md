# Security Policy

## Supported Versions

This project is in alpha. Security fixes target the `0.2.x` release series and
the current `main` development line.

## Reporting a Vulnerability

Report privately through GitHub's private vulnerability reporting, which is
enabled on this repository: open the Security tab and choose "Report a
vulnerability". Reports are handled privately through GitHub security advisories.

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

