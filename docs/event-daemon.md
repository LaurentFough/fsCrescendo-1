---
title: "Crescendo event daemon (crescendo-esd)"
description: "A root LaunchDaemon that runs eslogger on request and streams events to the Crescendo app over a user-only Unix socket: install, protocol, security model and limits."
slug: crescendo-event-daemon
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-08
date-modified: 2026-11-08
date-published:
source: "daemon/crescendo-esd.swift 0.2.0, scripts/esd-install.sh 1.1.0, scripts/esd-sign.sh 1.0.0, tools/cresc/cresc/esd.py 0.1.0"
domain: macos-security
url:
draft: true
tags:
  - macos
  - launchd
  - eslogger
keywords:
  - LaunchDaemon
  - Endpoint Security
  - Full Disk Access
---

# Crescendo event daemon

## What and why
`eslogger` (macOS 13+) prints Endpoint Security NOTIFY events as JSON but needs root and Full Disk Access (FDA).
Running it from a terminal each time is clumsy. `crescendo-esd` is a small LaunchDaemon that stays **idle** until the
app asks it to start `eslogger`; Start / Stop / Pause in the Events tab are then plain socket commands.
It needs no Endpoint Security entitlement of its own (Apple's `eslogger` carries it).

## Install (one admin prompt, once)
```bash
make esd-build          # swiftc, Command Line Tools are enough
make esd-install        # sudo: copies the binary, writes the plist, launchctl bootstrap
```
Then grant FDA to the daemon binary: System Settings > Privacy & Security > Full Disk Access > `+`, press
Cmd-Shift-G and enter `/Library/PrivilegedHelperTools/com.loff.crescendo.esd`.

```bash
make esd-status         # JSON: state idle|running, version
make esd-log            # /var/log/crescendo-esd.log (eslogger errors, e.g. missing FDA)
make esd-remove         # sudo: unload and delete
```
### Keep the Full Disk Access grant across rebuilds
macOS ties the grant to the daemon's signing requirement. An ad-hoc signature (the default) changes with every build,
so the grant is lost. Sign with a real identity **as your user** (root cannot use your keychain, so signing happens in
`make esd-sign` before `sudo`):
```bash
make esd-identities                     # list identities
make esd-install SIGN_IDENTITY=auto     # first "Apple Development" identity (Xcode > Settings > Accounts)
make esd-install SIGN_IDENTITY="Apple Development: Your Name (TEAMID)"   # or name / SHA-1 explicitly
```
The identity is only read from the environment; it is never written to the repository, so the project stays on
"Sign to Run Locally". A free Apple ID's Apple Development certificate is enough (no provisioning profile is needed
for a daemon without entitlements). A self-signed Keychain Access certificate works the same way.

### First-run check in the app
The Events tab asks the daemon for `status` (which includes an `fda` probe) and shows a banner:
- **daemon not installed** -> "Install daemon..." runs the bundled installer with an administrator prompt (builds made
  with `make build-lite` bundle it in `Contents/Resources/esd`); otherwise it offers to copy `make esd-install`;
- **no Full Disk Access** -> "Open Full Disk Access..." opens System Settings at Privacy & Security > Full Disk Access
  and reveals the daemon in Finder so you can drag it in;
- ready -> the banner disappears. The check repeats whenever the app becomes active again.

## Protocol (Unix socket `/var/run/com.loff.crescendo.esd.sock`)
| Client line | Reply |
|---|---|
| `status` | `{"esd":1,"ok":true,"state":"idle|running","version":"0.2.0","events":[...],"fda":true|false}` (`fda` absent = unknown) |
| `start EVENT [EVENT ...]` | `{"esd":1,"ok":true,"state":"running",...}` then raw `eslogger` JSON lines |
| `stop` | `{"esd":1,"ok":true,"state":"idle"}` |
Control replies always start with `{"esd"`. The engine (`cresc serve`) consumes them: `esd.status` returns
`available`, and `watch.start` accepts `source: {"socket": PATH, "events": [...]}`.

## Security model
- Socket file: owner = the installing user, mode `0600`; the daemon also checks every connection with `getpeereid()`
  (only that uid, or root). The stream is system-wide, so no other local user or process may read it.
- Event names are `[a-z_]{1,40}`, at most 40; one stream at a time; `eslogger` is stopped when the client disconnects or
  on SIGTERM. The daemon never executes anything but the configured `eslogger` path.
- Trust note: any process running as **you** can start the stream. The app does not hide events from your own user; a
  stricter model (code-signature check of the client) needs a stable signing identity and is not implemented.
- Limits: NOTIFY events only (no blocking), as with `eslogger`; a slow client makes `eslogger` drop events (the engine
  reports gaps via `global_seq_num`).

## Status
Spike: written without a Mac in reach, so it is **untested on real hardware**. The Python client and the protocol are
covered by tests against a fake daemon (`tests/test_esd.py`). The first `make esd-build && make esd-install` is the test.

## References
```bibtex
@misc{apple_launchd_jobs,
  title        = {Creating Launch Daemons and Agents},
  author       = {{Apple Inc.}},
  howpublished = {Apple Developer Documentation Archive},
  url          = {https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html}
}
@misc{apple_endpoint_security,
  title        = {Endpoint Security},
  author       = {{Apple Inc.}},
  howpublished = {Apple Developer Documentation},
  url          = {https://developer.apple.com/documentation/endpointsecurity}
}
```
