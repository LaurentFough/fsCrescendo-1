---
title: "Crescendo lite build (no Endpoint Security entitlement)"
description: "How to build and run Crescendo on an unmodified Mac, what the lite build can and cannot do, and how it relates to the cresc engine."
slug: crescendo-lite-build
author: "Clauiri (Claude Code session) for the repository owner"
type: how-to
date-created: 2026-11-08
date-modified: 2026-11-08
date-published:
source: "Makefile 1.8.0, scripts/lite-package.sh 1.0.0"
domain: macos-security
url:
draft: true
tags:
  - macos
  - build
  - endpoint-security
keywords:
  - lite build
  - AMFI
  - entitlements
---

# Crescendo lite build

## Why
The stock app embeds a system extension that holds `com.apple.developer.endpoint-security.client`. Apple must approve
that entitlement; an ad-hoc signed app carrying it is killed by AMFI at launch unless SIP/AMFI are relaxed.
The **lite** build removes the extension and signs the app with an *empty* entitlements file
(`Crescendo/CrescendoLite.entitlements`), so it launches on a normal Mac.

## Build and run
```bash
make doctor
make build-lite
open build/lite/Crescendo.app
```
`build-lite` builds unsigned, then `scripts/lite-package.sh` copies the app, deletes
`Contents/Library/SystemExtensions`, ad-hoc signs ("Sign to Run Locally"), and verifies that no
`com.apple.developer.*` entitlement and no extension remain (it fails otherwise).

## What works / what does not
| Area | Lite build |
|---|---|
| App launches with SIP and AMFI on | yes (expected; verify on your Mac: `make verify-sign`) |
| Start button (system extension) | shows an explanation instead of crashing |
| Live events inside the app | not yet: step 1 connects the app to `cresc serve` (eslogger) |
| Sandbox denials / grants | via `cresc` today (CLI and `cresc serve`) |

## Notes
- Verified here only by static checks (Linux): the Swift change type-checks nowhere in this environment, so the first
  `make build-lite` on your Mac is the real test. Send me the output if it fails.
- The full ES build is unchanged: `make build` (needs a relaxed VM to run).

## Cresc console (step 1a)
Menu bar item **Cresc Console...** opens a window driven by the bundled engine (`Contents/Resources/cresc-engine`,
started as `python3 -m cresc serve`; override with `CRESC_PYTHON` / `CRESC_ENGINE_DIR`):
- **Sessions**: profile, program, write dirs (`:`-separated), arguments; Start / Stop / Restart.
- **Denials**: candidates from the last run with their generated rules; Grant selected, Grant all low-risk,
  Grant selected & restart (high-risk rules ask for confirmation first).
- **Events** (preferred: event daemon, see `docs/event-daemon.md`; `make esd-install` once, then Start / Stop / Pause need no
  Terminal or password; Pause really stops eslogger). Without the daemon: pick a scope (all / app / dir / file / pid), optionally a kinds filter, press **Start**. The app asks the
  engine to read a private FIFO (`~/Library/Application Support/Crescendo/es/events.fifo`, 0600) and opens a Terminal
  window running `sudo eslogger ... > fifo` (generated `run-eslogger.command`, 0700); type your sudo password there.
  **Stop** closes the FIFO and eslogger exits on its next write. Terminal needs Full Disk Access; the app needs no
  privileges or entitlements. 5000 rows are kept, with search, pause and autoscroll.

## Console reference (v0.2)
- **Sessions**: profile (pick or type), program (Choose...), *Write folders* and *Arguments* as editable rows with
  `Add...` (file/folder dialog), `+`, `-` and drag-and-drop from the Finder. Entries are remembered between launches.
  Every control has a tooltip.
- **Denials**: run picker (new runs appear automatically), `Candidates | All` filter, search, a Change column
  (new / persisting vs the previous run; resolved ones are counted in the summary), a detail box (why it was classified,
  the rule, notes), and the buttons Grant selected, Grant selected & restart, Grant all low-risk, Grant up to medium,
  Add rule by hand, **Export evidence...** and **Verify bundle...** (see below).
- **Profile**: history of every change, the sandbox text of the selected version, Diff with previous, Revoke selected grant.
- **Events**: see above; kinds are rows; the scope has a picker.

## Evidence bundle (investigation proof)
Denials tab > **Export evidence...** writes one zip for the shown run (CLI: `python3 -m cresc export NAME --run N -o out.zip`):
`run/` (record, program output escaped, denials as logged), `analysis/` (triage JSON, CSV, comparison with the previous
run), `profile/` (the exact sandbox profile used, grants and history, the diff that led to it), optional `events/`
(an eslogger capture via `--events FILE`), a PKIM-ready `README.md`, and `manifest.json` with the SHA-256 of every file.
- **Verify** with **Verify bundle...** or `python3 -m cresc verify-bundle out.zip`: reports changed, missing and extra files.
- The manifest is inside the zip, so this is tamper-*evident*. For proof, store the zip's own SHA-256 (logged on export)
  somewhere separate.
- Your home folder path becomes `~` by default; other personal data is not removed, so review before sharing.
