---
type: architecture
title: Collection and report flow
description: Trace validated snapshot inputs, bounded GitHub observations and deterministic output handling.
tags: [collection, github, reports]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-16T15:39:14.997Z
sources:
  - id: openwiki-source-70e902a90f1729aeec281078
    resource: repo://src/ghorgsec/cli.py
  - id: openwiki-source-4c0bb2eeb58212a3caebcf0f
    resource: repo://src/ghorgsec/github_client.py
  - id: openwiki-source-1199b6b14453371110d0d7f1
    resource: repo://src/ghorgsec/live_collector.py
generated: { by: "codex", at: "2026-10-16T15:30:15.076Z" }
---

# Collection and report flow

## Select one source

The CLI selects a synthetic stub, a local JSON snapshot or explicit live collection. Offline routes do not read token environment variables. Fixture input supplies the owner; an organization override or live/user mode cannot be combined with it. A repository selector can restrict a validated fixture to a documented subset ([CLI routing](../../src/ghorgsec/cli.py#L45-L108), [fixture selection](../../src/ghorgsec/cli.py#L195-L228)).

Live personal collection verifies the requested username against the authenticated account. Organization collection verifies its owner identity. Both paths enumerate token-visible repositories and reject requested names absent from that inventory. Repository IDs must be positive integers and unique; metadata with another ID or name aborts collection before control queries. These checks detect identity changes during collection, but cannot make sequential observations atomic ([inventory](../../src/ghorgsec/live_collector.py#L18-L105), [metadata identity](../../src/ghorgsec/live_collector.py#L117-L135)).

## Network boundaries

The transport issues GET requests, refuses redirects and validates a fixed HTTPS origin. The client limits requests, pages, individual response bytes and cumulative inventory bytes before decoding each page. Pagination follows the server's next link on the same resource and filters, with increasing numeric pages. Time budgets bound the checked operations without promising a wall-clock SLA ([transport](../../src/ghorgsec/github_client.py#L70-L145), [collection budgets](../../src/ghorgsec/github_client.py#L148-L245)).

Rate limits fail without automatic retries. Diagnostics include only validated numeric remaining/reset/retry-after values. Other headers, credentials and remote response bodies are not copied into errors. Inaccessible individual controls remain gaps; an unavailable inventory or failed collection does not become a completed partial report ([errors](../../src/ghorgsec/github_client.py#L172-L198), [rate limits](../../src/ghorgsec/github_client.py#L248-L294)).

## Output boundaries

A snapshot feeds coverage, the existing risk rubric and suggested next steps. Markdown preserves supplied text under the documented CommonMark contract; JSON retains the original values. The CLI writes UTF-8/LF output and refuses an output path aliasing a source fixture. Comparison protects both supplied files. Invalid input or output operations use exit2 ([output](../../src/ghorgsec/cli.py#L113-L184), [rendering](../../src/ghorgsec/report.py)).

See [posture semantics](../concepts/posture-semantics.md) before interpreting coverage and [snapshot review](../workflows/snapshot-review.md) before treating a difference as a change on GitHub. Focused tests exercise client boundaries, fixture selection and output preservation without requiring a live organization.
