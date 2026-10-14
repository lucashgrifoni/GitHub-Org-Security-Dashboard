---
type: "architecture"
title: "Collection and report flow"
description: "Trace input selection, fixed-origin GET collection and deterministic output handling."
tags: ["collection","github","reports"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:10:41.356Z
sources:
  - id: openwiki-source-70e902a90f1729aeec281078
    resource: repo://src/ghorgsec/cli.py
  - id: openwiki-source-4c0bb2eeb58212a3caebcf0f
    resource: repo://src/ghorgsec/github_client.py
  - id: openwiki-source-1199b6b14453371110d0d7f1
    resource: repo://src/ghorgsec/live_collector.py
generated: { by: "codex", at: "2026-10-14T19:10:41.356Z" }
---

# Collection and report flow

## CLI selects one input route

Fixture mode rejects combinations with live/user, org or repo selectors, because those values would conflict with the fixture's own identity. Live personal mode verifies the requested username against the authenticated account. Live organization mode verifies the organization identity, pages the inventory and rejects requested repositories absent from that inventory ([CLI routing](../../src/ghorgsec/cli.py#L89-L116), [live inventory](../../src/ghorgsec/live_collector.py#L18-L78)). These checks limit the snapshot's identity; they do not prove full account coverage.

## The client owns network boundaries

The transport issues GET requests. URL validation fixes the HTTPS origin to `api.github.com`; the transport refuses redirects. The client applies request, page, response-size and time budgets ([GitHub REST client](../../src/ghorgsec/github_client.py)). The live collector observes modeled control settings and emits unknown/not-collected states and warnings when the available response cannot establish the state.

## Reports own output format

The selected snapshot is rendered in Markdown or JSON and written to stdout or a requested local file. The CLI refuses to overwrite its input fixture and pins output text to UTF-8 with LF bytes. Its error path writes an operator error and exits 2 ([output handling](../../src/ghorgsec/cli.py#L116-L166), [fixture/error helpers](../../src/ghorgsec/cli.py)). The output is an observation record, not a configuration mutation.

The tests under `tests/` cover CLI, fixture, report and live-client contracts with local or mocked inputs. See [posture semantics](../concepts/posture-semantics.md) before interpreting percentages.
