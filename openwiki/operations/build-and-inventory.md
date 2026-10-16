---
type: operations
title: Build and runtime inventory
description: Understand frozen Python inputs, installed-wheel qualification and platform-scoped dependency evidence.
tags: [build, inventory, supply-chain]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-16T16:05:30.374Z
sources:
  - id: openwiki-source-164e2da859b5277df81c7d94
    resource: repo://.github/workflows/ci.yml
  - id: openwiki-source-755c44321da69ed14de0f8d4
    resource: repo://.github/workflows/secrets-hygiene.yml
  - id: openwiki-source-c9cd1e222fe54637129c8ea3
    resource: repo://scripts/build_sbom.py
generated: { by: "codex", at: "2026-10-16T16:05:30.374Z" }
---

# Build and runtime inventory

## Frozen Python inputs

Runtime and development lockfiles record versions and archive hashes. Development inputs include the build backend and editable-install support. CI installs these inputs before installing the project without resolving another dependency graph. Release builds use the installed backend and a commit-derived source timestamp ([build configuration](../../pyproject.toml), [CI](../../.github/workflows/ci.yml), [release workflow](../../.github/workflows/release.yml)).

These controls do not freeze the operating system, every runner detail or interpreter version. A reproducibility claim requires comparing rebuilt bytes under a declared environment. The [build guide](../../docs/RELEASE.md) describes commands and scope.

## Installed runtime boundary

The quality matrix declares Ubuntu/Python 3.12 and 3.13 and Windows/Python 3.12. Each lane builds a wheel, installs its frozen runtime into a clean environment, installs the wheel without dependency resolution, checks consistency, exercises offline CLI journeys and generates a runtime inventory. The aggregate quality job depends on all quality lanes and the package job. These are configured checks, not proof that a particular remote run passed ([matrix](../../.github/workflows/ci.yml)).

The smoke runner uses an installed distribution outside the source tree, blocks network connections, compares stdout/file bytes and exercises report, fixture selection and snapshot comparison ([installed smoke](../../scripts/smoke_installed.py)).

## SBOM meaning

The generator consumes installer reports for the same environment. It checks the application archive digest and constructs dependency edges using active PEP 508 markers and requested extras. Missing or incompatible active dependencies, duplicate/yanked components and packages outside the application runtime closure are rejected ([graph and identity](../../scripts/build_sbom.py#L23-L108)).

Components use declared SPDX expressions when supplied. Legacy license text and classifier names stay literal; broad license families are not converted into inferred SPDX identifiers. Missing declarations remain explicit. SHA-256 values describe distribution archives recorded by the installer, not every extracted file ([metadata](../../scripts/build_sbom.py#L111-L146)).

Each inventory names its Python/system scope and application archive. Conditional dependencies can differ between platforms. Qualification inventories describe the wheel built in their own lane; they must not be silently rebound to another published archive. Reports can also come from a dry-run, so reports alone do not establish successful installation or use.

The release workflow declares provenance and runtime-SBOM attestations with exact package subjects. Inventory, advisory checks and provenance answer different questions; none certifies application security or legal compliance ([attestation configuration](../../.github/workflows/release.yml)).

## Source repository secrets gate

The secrets workflow scans the repository history and evaluates active findings at high severity. Its job fails on BLOCK, scanner/processing errors or a missing valid decision, and retains normalized reports even on failure. The existing controlled examples exercise PASS, BLOCK and operational error exits. The [gate guide](../../docs/secrets-hygiene-pilot.md) describes exception and recovery boundaries ([workflow](../../.github/workflows/secrets-hygiene.yml)).

Making this check mandatory for merges is a separate GitHub branch-protection setting. The workflow file alone does not prove that setting is active. This source-repository check does not add secret-content collection to the dashboard's target repositories.
