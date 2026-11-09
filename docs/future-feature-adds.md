---
title: "Future feature adds"
description: "Parked ideas for Crescendo and cresc, kept so they are not lost: FSMonitor-inspired file activity features and earlier deferred items."
slug: future-feature-adds
author: "Clauiri (Claude Code session) for the repository owner"
type: backlog
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "conversation notes; FSMonitor documentation https://fsmonitor.com/Documentation/"
domain: macos-security
url:
draft: true
tags:
  - backlog
  - ideas
keywords:
  - future-feature-adds
  - file activity
---

# Future feature adds

## Ideas worth borrowing from FSMonitor (none started)
- [ ] **Pruning mode**: hide create-then-delete noise (and repeated modifies of one file).
- [ ] **Tree view** of changed paths with event counts.
- [ ] **Hide a directory with one key** (Delete hides the subtree, Cmd-Delete reveals it).
- [ ] **Save and reopen recordings as documents.**
- [ ] **Record session info** (host, time, macOS version) in exports.

Also from the FSMonitor feature list (see `docs/plan-file-activity-view.md`): three display modes (tree, list, text), filter
by path / event category / process with saved filter templates, inspector with the exact kind of change, export as JSON
or plain text, command-line tool for automation, graph visualisation of file activity (planned as its own feature).

## Added 2026-11-09
- [ ] **Remote lab source**: run `cresc serve` and the event daemon in a macOS VM (disposable snapshots, SIP can stay on for
  `eslogger`) and connect the app to it over SSH or vsock; the app shows guest activity as another event source.
- [ ] Record player for `.crescrec` documents (play/pause, speed, scrub) is part of the file-activity plan, not parked.
- [ ] Optionally request Apple's Endpoint Security entitlement in parallel (only useful for blocking/AUTH events).

## Parked earlier (decisions pending)
- [ ] Event daemon: stop other processes of the same user from starting the stream (client code-signature check).
- [ ] Attach Events-tab rows to evidence bundles automatically (resolved by recordings in the plan above).
- [ ] Optional signing of evidence bundles.
- [ ] CLI default write folder (CLI still requires `--write-dir`).
- [ ] Real `eslogger` captures for create/rename to a NEW path, `uipc_connect`/`uipc_bind`, mount.
- [ ] Baseline run of the original Crescendo in a SIP/AMFI-relaxed VM.
- [ ] Remaining P0 audit items: COR-08, SEC-01, SEC-02, SEC-04, REL-01, BLD-01, BLD-03.
