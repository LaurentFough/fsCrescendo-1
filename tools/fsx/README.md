---
title: "fsx: sandbox-denial triage and managed sandbox sessions"
description: "Engine for the local inspector: runs a program under a versioned deny-default sandbox profile, collects its Seatbelt denials, suggests allow rules, and restarts it under the updated profile."
slug: fsx-readme
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-07
date-modified: 2026-11-07
date-published:
source: "tools/fsx, version 0.1.0"
domain: macos-security
url:
draft: true
tags:
  - macos
  - sandbox-exec
  - python
keywords:
  - sandbox-exec
  - denials
  - profiles
---

# fsx

Standard-library Python (3.9+), no dependencies. Everything except actually running a program is pure logic and is tested on any OS (`make fsx-test`).

## What it does (the workflow)

1. **Create or load a profile**: a deny-default Seatbelt profile with a baseline and a list of approved grants. Every change makes an immutable snapshot (`v1.sb`, `v2.sb`, ...).
2. **Run** a program under the current profile version. The program gets no stdin, its output goes to files in the run directory, and its denials are read from the unified log.
3. **Review** the denials: harmless noise is separated from real candidates, each candidate gets a risk level and the narrowest allow rule that would permit it.
4. **Grant** the rules you approve. High-risk rules (writes, exec, fork, network, sensitive paths) need an explicit confirmation.
5. **Kill and restart**: the whole process tree is stopped and the program is started again under the new version. `fsx compare` shows which denials the change resolved.

```bash
cd tools/fsx                                   # or: PYTHONPATH=tools/fsx python3 -m fsx ...
python3 -m fsx profile new demo
python3 -m fsx loop demo --target ./the-binary --write-dir ~/tmp/_sandbox -- --its-flags
#   run -> shows denials -> "g low" grants the low-risk ones -> restarts under v2 -> ...
python3 -m fsx runs demo
python3 -m fsx compare demo 1 2
python3 -m fsx profile diff demo 1 2
```

Non-interactive pieces (what a GUI calls):

| Command | Purpose |
|---|---|
| `fsx parse [FILE]` | log lines to grouped denials (`--json`: `fsx.denials/1`) |
| `fsx triage [FILE]` or `--profile P --run N` | classify, risk, suggested rules (`--json`: `fsx.triage/1`) |
| `fsx profile new/list/show/path/history/diff/revoke/grant` | versioned profiles (`fsx.profile/1`) |
| `fsx run NAME --target T --write-dir D [--watch NAME] [--timeout S] -- ARGS` | one run (`--json`: `fsx.run/1`) |
| `fsx runs NAME`, `fsx compare NAME A B` | run history and what a profile change resolved |
| `fsx loop NAME ...` | interactive run / grant / restart |

Program arguments go after a literal `--`. Data lives in `$FSX_HOME` (default `~/.local/share/fsx`).

## Safety rules built in

- The program starts **inside its first write directory**, never in the directory you launched fsx from, and receives only a
  safe set of environment variables (`PATH HOME USER LOGNAME LANG LC_ALL LC_CTYPE TERM TMPDIR TZ`). Tokens and API keys in your
  shell stay out of its reach; add variables with `--pass-env NAME`, or everything with `--inherit-env`. Run records list
  variable names only, never values.
- Write directories must be absolute and not symlinks; `/`, `$HOME` and its ancestors are refused; directories fsx creates get mode 700, existing ones are not touched.
- Generated rules are **allows only**; strings are escaped and control characters refused; a profile that does not parse is never saved.
- Grants that need confirmation are all-or-nothing: if any selected rule needs `--confirm` and it is missing, nothing is granted.
- Network grants are protocol and port only (the sandbox cannot filter by host, see `docs/sandbox-semantics.md`).
- Harmless denials (DTrace helper, Rosetta check, syslog socket, notification center, PATH-search stats) are listed with a reason and never suggested for granting.

## Testing hooks

`FSX_SANDBOX_EXEC` and `FSX_LOG` replace `sandbox-exec` and `/usr/bin/log` (the tests use fakes). On a Mac, `log` must be `/usr/bin/log`: in zsh a bare `log` is a shell builtin.

## Not in scope

Anything that needs Apple's Endpoint Security entitlement: live allow/deny of arbitrary running processes and a system extension of our own. The existing extension code in this repository is not used by fsx.

## Known gaps

- File operations in grants rely on the same last-rule-wins behaviour that was measured for network rules; `make probe-sandbox-net` covers networking only.
- Unix-socket grants (`remote unix-socket`) have unverified syntax and always require confirmation.
- The format of network denial lines in the log has not been observed yet; such lines are parsed generically (`host:port` or a socket path).
