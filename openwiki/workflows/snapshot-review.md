---
type: workflow
title: Review stored security snapshots
description: Select and compare captured observations without collecting new GitHub data or inferring remediation.
tags: [snapshots, comparison, review]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-16T15:30:15.076Z
sources:
  - id: openwiki-source-70e902a90f1729aeec281078
    resource: repo://src/ghorgsec/cli.py
  - id: openwiki-source-0eac4e57f9a1df6a1591c6fd
    resource: repo://src/ghorgsec/comparison.py
generated: { by: "codex", at: "2026-10-16T15:30:15.076Z" }
---

# Review stored security snapshots

## Select a local subset

Report mode can select repositories from a local snapshot. The loader validates the entire JSON before selection. Matching ignores case and surrounding selector whitespace, preserves source order and rejects absent or ambiguous names. A subset warning makes the resulting coverage boundary explicit. Importing a report always uses fixture mode; it does not create a new live observation ([selection](../../src/ghorgsec/cli.py#L195-L228), [fixture parsing](../../src/ghorgsec/fixture_loader.py#L103-L116)).

## Compare compatible observations

The comparison command loads two local snapshots without reading credentials or using the network. Owners must match exactly, timestamps must contain timezones, and the current timestamp cannot precede the baseline. Equal timestamps are accepted with a warning. Imported scores and summaries do not define the changes; the comparison uses the four supplied control states ([command](../../src/ghorgsec/cli.py#L113-L138), [comparison](../../src/ghorgsec/comparison.py#L35-L99)).

Repository names match exactly during comparison. Added or missing names describe membership in the supplied files. Permissions, filtering, partial collection or renaming can explain a difference; it does not prove repository creation or deletion.

## Interpret transitions

| Classification | Meaning |
|---|---|
| `enabled_observed` / `disabled_observed` | Transition between two supplied known states |
| `evidence_gained` | An evidence gap becomes a supplied known state |
| `evidence_lost` | A supplied known state becomes an evidence gap |
| `gap_changed` | One kind of gap changes into another |
| `scope_changed` | The default branch changes, so branch-protection scope differs |

Default-branch scope changes take precedence over its control-state transition. These classifications do not establish remediation, current enforcement or authentic collection provenance ([classification](../../src/ghorgsec/comparison.py#L73-L89), [state transitions](../../src/ghorgsec/comparison.py#L113-L121)). See [posture semantics](../concepts/posture-semantics.md) for ratings and suggested review steps.

## Preserve evidence files

Both comparison inputs are protected against output-path aliases, including resolved paths and hard links. Other existing output files can be replaced, so keep distinct names when preserving history. Malformed or incompatible inputs fail before the output writer opens a destination ([output handling](../../src/ghorgsec/cli.py#L113-L184)). The README contains runnable synthetic examples; synthetic differences are not observations of a real organization.
