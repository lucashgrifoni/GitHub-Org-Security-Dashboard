---
type: quickstart
title: GitHub repository posture reports
description: Choose offline reports, stored-snapshot review, explicit live observations or build inventory tasks.
tags: [github, posture, cli]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-16T15:30:15.076Z
sources:
  - id: openwiki-source-70e902a90f1729aeec281078
    resource: repo://src/ghorgsec/cli.py
  - id: openwiki-source-1199b6b14453371110d0d7f1
    resource: repo://src/ghorgsec/live_collector.py
generated: { by: "codex", at: "2026-10-16T15:30:15.076Z" }
---

# GitHub repository posture reports

The report command renders a modeled snapshot in Markdown or JSON. Synthetic repository names and local snapshots are offline inputs; GitHub collection requires an explicit live choice. Token environment variables are read only for that live route. Stored-snapshot comparison is also offline ([CLI routing](../src/ghorgsec/cli.py#L45-L138)).

## Start offline

Use the installation and synthetic examples in the [README](../README.md). Python 3.12 or newer is required and the package installs the ghorgsec entrypoint ([package metadata](../pyproject.toml)). A local snapshot can be selected down to repositories or compared with another compatible snapshot. These operations interpret supplied data; they do not collect new evidence from GitHub.

## Choose a task

| Task | Page |
|---|---|
| Trace inputs, fixed-origin reads and report output | [Collection and report flow](architecture/collection-and-report.md) |
| Interpret gaps, coverage, ratings and next steps | [Posture semantics](concepts/posture-semantics.md) |
| Select repositories and compare captured snapshots | [Snapshot review](workflows/snapshot-review.md) |
| Understand frozen inputs, installed wheels and SBOM scope | [Build and runtime inventory](operations/build-and-inventory.md) |
| Maintain this documentation integration | [OpenWiki setup](../docs/openwiki.md) |

## Live boundary

Use only an owned or authorized target. Live inventory is limited to token-visible repositories and observations are sequential. Identity and pagination checks detect some inconsistencies without proving complete coverage or atomicity. Default-branch protection is an observed setting, not proof of enforcement quality or vulnerability absence ([live collector](../src/ghorgsec/live_collector.py#L18-L84)). Read warnings together with the output and consult the [live contract](../docs/LIVE_COLLECTION.md) for permissions and API limits.
