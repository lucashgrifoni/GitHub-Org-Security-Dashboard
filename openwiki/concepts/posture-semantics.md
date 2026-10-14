---
type: "concept"
title: "Posture and collection semantics"
description: "Interpret four modeled controls without treating uncollected or unknown state as confirmed coverage."
tags: ["posture","risk","coverage"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:10:41.356Z
sources:
  - id: openwiki-source-d91fed0bdf169594703376d2
    resource: repo://src/ghorgsec/risk.py
  - id: openwiki-source-5929f1cf6e538a0290462469
    resource: repo://src/ghorgsec/summary.py
generated: { by: "codex", at: "2026-10-14T18:52:35.067Z" }
---

# Posture and collection semantics

## State and denominator

The summary aggregates branch protection, secret scanning, code scanning and Dependabot alerts. `not_collected` is excluded from the coverage denominator; `unknown` remains in it. Coverage is the integer floor of enabled times 100 divided by enabled + disabled + unknown, returning zero if that denominator is zero ([summary](../../src/ghorgsec/summary.py#L14-L61)). A zero value without collected controls therefore carries a different meaning from observed disabled controls.

## Rating is a transparent rubric

The rating weights disabled as 2, unknown as 1 and enabled as 0, excluding not-collected controls. With no assessed controls the rating is `not_assessed`; otherwise score 0 is strong, scores 1–2 moderate and scores 3 or more weak. The assessment-status property separately identifies absent, partial or complete collection ([rubric](../../src/ghorgsec/risk.py)). A strong label applies to this rubric's observed fields and is not a security certification.

## Preserve collection limits

The live collector's warnings describe non-atomic collection, token visibility and default-branch scope. Do not promote a repository state into account-wide coverage or enforcement quality ([warnings](../../src/ghorgsec/live_collector.py#L55-L67)). Return to [collection flow](../architecture/collection-and-report.md) to trace where a warning originated, or [quickstart](../quickstart.md) to select an input mode.
