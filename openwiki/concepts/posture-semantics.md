---
type: concept
title: Posture states, coverage and review steps
description: Interpret coverage, ratings and suggested next steps without
  confusing evidence gaps with disabled controls.
tags:
  - posture
  - risk
  - coverage
verified:
  - by: openwiki/0.7.2
    at: 2026-10-16T16:23:41.573Z
sources:
  - id: openwiki-source-392b215c646c65e1e6087d3f
    resource: repo://src/ghorgsec/actions.py
  - id: openwiki-source-d91fed0bdf169594703376d2
    resource: repo://src/ghorgsec/risk.py
  - id: openwiki-source-5929f1cf6e538a0290462469
    resource: repo://src/ghorgsec/summary.py
generated: { by: "codex", at: "2026-10-16T15:39:14.997Z" }
---

# Posture states, coverage and review steps

## States and coverage

The four controls are branch protection, secret scanning, code scanning and Dependabot alerts. `not_collected` is excluded from coverage; `unknown` remains in the denominator. Coverage is the integer floor of enabled times 100 divided by enabled + disabled + unknown. The numeric value is zero for an empty denominator, while serialization exposes `coverage_status=not_assessed` so consumers can distinguish that case ([coverage](../../src/ghorgsec/summary.py#L23-L60), [JSON fields](../../src/ghorgsec/serialize.py#L80-L98)).

An all-unknown control has an assessed denominator and zero enabled coverage. It is not a control that was never collected, and does not establish that the configuration is disabled.

## Ratings and collection completeness

The rubric assigns 2 points to disabled, 1 to unknown and 0 to enabled; not-collected controls are excluded. With no assessed controls, rating is `not_assessed`. Otherwise score 0 is strong, scores 1 or 2 moderate, and scores 3 or more weak. `assessment_status` separately records complete, partial or absent collection ([rubric](../../src/ghorgsec/risk.py#L48-L114)).

A complete assessment can still contain unknown controls: complete means no field is `not_collected`. A strong label applies only to the supplied fields and rubric. It does not certify security or enforcement.

## Suggested review steps

The planner creates one item for each non-enabled control. Disabled suggests reviewing configuration, unknown suggests checking evidence access, and not-collected suggests collecting evidence. Enabled creates no suggestion. Items are ordered by the exact repository name and modeled control order; the planner neither changes configuration nor modifies the score ([planner](../../src/ghorgsec/actions.py#L8-L42)).

## Observation limits

Live warnings preserve token visibility, sequential collection and default-branch scope. Advanced scanning can remain unknown when the default-setup endpoint cannot establish current configuration. The absence of a finding is not an absence-of-vulnerability claim. See [collection flow](../architecture/collection-and-report.md) and [snapshot review](../workflows/snapshot-review.md) before interpreting a changed state as remediation.
