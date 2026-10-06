# Security Policy

## Supported Versions

This project is in alpha. Security fixes target the `0.3.x` release series and
the current `main` development line.

## Reporting a Vulnerability

Report privately through GitHub's private vulnerability reporting, which is
enabled on this repository: open the Security tab and choose "Report a
vulnerability". Reports are handled privately through GitHub security advisories.

Include the affected version or commit, reproduction steps, and expected
impact. For offline parsing issues, include a minimal synthetic fixture. For live
collection issues, include sanitized HTTP status codes and synthetic response data.

Do not include GitHub tokens, private repository names, organization secrets,
customer data, or sensitive audit exports in public issues.

## Data Handling

Offline reports do not read credentials or call GitHub. Explicit `--live` uses
`GH_TOKEN` or `GITHUB_TOKEN` for GET requests to `api.github.com` only. Redirects
are refused. Tokens and response bodies are excluded from reports and errors.
The collector reads repository metadata and control settings, not secret values
or vulnerability alert contents. It does not change repository configuration.

Live reports can contain private repository names and control posture. Keep them
in an appropriate local destination and review them before sharing. No reports
are uploaded or cached by the tool. Credential privileges and the system TLS
trust store remain part of the operator's environment. Prefer a token restricted
to the intended repositories with the documented read permissions.

See [the live collection contract](docs/LIVE_COLLECTION.md) for API sources,
limits, permission gaps and incomplete coverage. An enabled setting does not
establish enforcement quality or absence of vulnerabilities.
