---
type: "quickstart"
title: "GitHub repository posture reports"
description: "Choose offline fixtures or explicit live collection and route to posture interpretation."
tags: ["github","posture","cli"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:10:41.356Z
sources:
  - id: openwiki-source-70e902a90f1729aeec281078
    resource: repo://src/ghorgsec/cli.py
  - id: openwiki-source-1199b6b14453371110d0d7f1
    resource: repo://src/ghorgsec/live_collector.py
generated: { by: "codex", at: "2026-10-14T18:52:35.067Z" }
---

# GitHub repository posture reports

The `ghorgsec report` command renders a modeled repository snapshot as Markdown or JSON. It uses synthetic repository names or a local JSON fixture unless `--live` is explicitly selected. Token environment variables are read only in that live branch ([CLI](../src/ghorgsec/cli.py)).

## Start offline

Use the installation and fixture examples in the [README](../README.md). The package requires Python 3.12 or newer and installs the `ghorgsec` entrypoint ([package metadata](../pyproject.toml)). Offline reports are useful for reproducible interpretation; synthetic names are not live repository evidence.

## Choose a task

| Task | Page |
|---|---|
| Trace fixture, synthetic and GitHub inputs into a report | [Collection and report flow](architecture/collection-and-report.md) |
| Interpret unknown, not-collected, coverage and rating | [Posture semantics](concepts/posture-semantics.md) |
| Install and maintain this documentation integration | [OpenWiki setup](../docs/openwiki.md) |

## Live boundary

Live inventory is restricted to token-visible repositories and is collected sequentially. Default-branch protection is an observed configuration, not proof of enforcement quality or absence of vulnerabilities ([live collector](../src/ghorgsec/live_collector.py#L18-L78)). Review warnings alongside the output, and use the contribution guide's checks before changing report contracts.
