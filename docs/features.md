---
title: "Crescendo feature list and verification status"
description: "Every feature, where to find it, what it needs, and whether it has been verified on a Mac or is implemented and awaiting its first on-device test."
slug: crescendo-features
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "owner's test reports in the project conversation up to 2026-11-09; automated tests"
domain: macos-security
url:
draft: false
tags:
  - features
  - status
keywords:
  - feature list
  - verification
---

# Features and status

**Status values**
- **Verified**: the project owner ran it on a Mac and reported that it works (date in the notes).
- **Tested (engine)**: covered by the automated tests of the `cresc` engine (runs on Linux and macOS in CI). The engine tests do not cover the Swift app.
- **Awaiting test**: implemented, compiled by the owner (the build succeeds) but not yet reported as working on a Mac.

The Swift app cannot be compiled or run in the automated environment used to write it, so *Awaiting test* means exactly that.

## App

| Feature | Where | Needs | Status | Guide |
|---|---|---|---|---|
| Build and launch the lite app | `make build-lite` | Xcode | Verified (2026-11-08) | README |
| Menu bar icon, build line (version, build number, commit) | menu bar | | Awaiting test | user guide |
| Event daemon: `make esd-install`, `make esd-status` | terminal | admin password, FDA | Verified (2026-11-08) | [event-daemon](event-daemon.md) |
| In-app banners: Install daemon..., Open Full Disk Access... | Files view, Console > Events | admin password, FDA | Awaiting test | [event-daemon](event-daemon.md) |
| Live file activity: Start / Stop, List, Text, inspector | main window > File | daemon | Verified (2026-11-09) | user guide |
| Auto-scroll honoured, selection kept while capturing | File | daemon | Awaiting test (fixed 2026-11-09) | |
| File-type icons in the Path column and inspector | File | | Awaiting test | |
| Resizable details area (console tabs, main window) | console, main window | | Verified (2026-11-09) | |
| Dark mode text readable | everywhere | | Verified (2026-11-09) | |
| Cleanup modes (none / coalesce / prune) | File > Cleanup | daemon | Tested (engine); app Awaiting test | user guide |
| Pause / Resume (Space) | File | daemon | Awaiting test | |
| Filter panel (rules, All/Any, templates) | File > Filter | | Awaiting test | |
| Hide folder (Delete), restore (Command-Delete), row menu | File | | Awaiting test | |
| Tree view with rolled-up counts | File > Tree | | Awaiting test | |
| Graph view: horizontal tree and sunburst, scale filters, zoom, PNG export | File > Graph | | Awaiting test | |
| Record with pre-roll; recordings open as documents; player (play, speed, scrub) | File > Record, File menu > Open Recording | daemon | Engine Tested; app Awaiting test | [recording-format](recording-format.md) |
| Other main-window segments (All Events, Process, Network, Unsigned, Exclude Apple) | main window | original system extension | Not available in the lite build | |

## Cresc Console

| Feature | Where | Needs | Status |
|---|---|---|---|
| Engine starts, status line | Console header | Python 3 | Verified (2026-11-08) |
| Sessions: run under a sandbox profile, write folders, arguments, Start / Stop / Restart | Console > Sessions | `/usr/bin/sandbox-exec` | Engine Tested; real runs from the command line Verified (2026-11-07); app Awaiting test |
| Denials: candidates, grant (selected / low / medium / by hand), grant and restart, compare | Console > Denials | | Engine Tested; app Awaiting test |
| Profile history, diff, revoke | Console > Profile | | History display Verified (2026-11-09); diff and revoke Awaiting test |
| Events tab (scope, kinds) | Console > Events | daemon | Awaiting test |
| Evidence bundle export and verify | Console > Denials | | Engine Tested; app Awaiting test |
| Defaults: store in `~/.local/share/crescendo/cresc`, write folder in `~/.local/state/crescendo/sandbox` | | | Engine Tested; app Awaiting test |

## Engine (`python3 -m cresc`)

| Feature | Command | Status |
|---|---|---|
| Parse, classify and triage sandbox denials; synthesize allow rules | `parse`, `triage` | Tested (engine) |
| Versioned profiles with history, diff, grant, revoke | `profile ...` | Tested (engine) |
| Managed runs and the interactive loop | `run`, `loop` | Tested (engine, with fake tools); real macOS Verified |
| Event view from eslogger JSON, scoped to app / dir / file / pid | `watch` | Tested (engine) against a real capture |
| File-change view and cleanup modes | `watch --files --cleanup` | Tested (engine) against a real capture |
| Recordings: info, verify, export (text, csv, json, jsonl), replay | `recording ...` | Tested (engine) |
| Evidence bundles | `export`, `verify-bundle` | Tested (engine) |
| JSON-lines interface for the app | `serve` | Tested (engine) |
| Capture a validated eslogger sample of file actions | `scripts/capture-file-events.sh` | Verified (2026-11-09) |

## Known limits

- Notifications only: events can be watched, not blocked (blocking needs Apple's Endpoint Security entitlement).
- Network activity is not part of the event stream (`eslogger` has no TCP/UDP events); sandbox denials still show network attempts of sandboxed programs.
- Not notarized: first launch needs right-click > Open.
- Any process running as your user can ask the daemon for events (see [SECURITY.md](../SECURITY.md)).
