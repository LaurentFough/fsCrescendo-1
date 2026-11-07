---
title: "cresc: sandbox-denial triage and managed sandbox sessions"
description: "Engine for the local inspector: runs a program under a versioned deny-default sandbox profile, collects its Seatbelt denials, suggests allow rules, and restarts it under the updated profile."
slug: cresc-readme
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-07
date-modified: 2026-11-07
date-published:
source: "tools/cresc, version 0.2.0"
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

# cresc

*Renamed from `fsx` in 0.2.0.* The old data directory `~/.local/share/fsx` and the `FSX_HOME` variable are still honoured, so existing profiles and runs keep working. The test hooks are now `CRESC_LOG` and `CRESC_SANDBOX_EXEC`.

Standard-library Python (3.9+), no dependencies. Everything except actually running a program is pure logic and is tested on any OS (`make cresc-test`).

## What it does (the workflow)

1. **Create or load a profile**: a deny-default Seatbelt profile with a baseline and a list of approved grants. Every change makes an immutable snapshot (`v1.sb`, `v2.sb`, ...).
2. **Run** a program under the current profile version. The program gets no stdin, its output goes to files in the run directory, and its denials are read from the unified log.
3. **Review** the denials: harmless noise is separated from real candidates, each candidate gets a risk level and the narrowest allow rule that would permit it.
4. **Grant** the rules you approve. High-risk rules (writes, exec, fork, network, sensitive paths) need an explicit confirmation.
5. **Kill and restart**: the whole process tree is stopped and the program is started again under the new version. `cresc compare` shows which denials the change resolved.

```bash
cd tools/cresc                                   # or: PYTHONPATH=tools/cresc python3 -m cresc ...
python3 -m cresc profile new demo
python3 -m cresc loop demo --target ./the-binary --write-dir ~/tmp/_sandbox -- --its-flags
#   run -> shows denials -> "g low" grants the low-risk ones -> restarts under v2 -> ...
python3 -m cresc runs demo
python3 -m cresc compare demo 1 2
python3 -m cresc profile diff demo 1 2
```

Non-interactive pieces (what a GUI calls):

| Command | Purpose |
|---|---|
| `cresc parse [FILE]` | log lines to grouped denials (`--json`: `cresc.denials/1`) |
| `cresc triage [FILE]` or `--profile P --run N` | classify, risk, suggested rules (`--json`: `cresc.triage/1`) |
| `cresc profile new/list/show/path/history/diff/revoke/grant` | versioned profiles (`cresc.profile/1`) |
| `cresc run NAME --target T --write-dir D [--watch NAME] [--timeout S] -- ARGS` | one run (`--json`: `cresc.run/1`) |
| `cresc runs NAME`, `cresc compare NAME A B` | run history and what a profile change resolved |
| `cresc loop NAME ...` | interactive run / grant / restart |

Program arguments go after a literal `--`. Data lives in `$CRESC_HOME` (default `~/.local/share/cresc`).

## Safety rules built in

- The program starts **inside its first write directory**, never in the directory you launched cresc from, and receives only a
  safe set of environment variables (`PATH HOME USER LOGNAME LANG LC_ALL LC_CTYPE TERM TMPDIR TZ`). Tokens and API keys in your
  shell stay out of its reach; add variables with `--pass-env NAME`, or everything with `--inherit-env`. Run records list
  variable names only, never values.
- Write directories must be absolute and not symlinks; `/`, `$HOME` and its ancestors are refused; directories cresc creates get mode 700, existing ones are not touched.
- Generated rules are **allows only**; strings are escaped and control characters refused; a profile that does not parse is never saved.
- Grants that need confirmation are all-or-nothing: if any selected rule needs `--confirm` and it is missing, nothing is granted.
- Network grants are protocol and port only (the sandbox cannot filter by host, see `docs/sandbox-semantics.md`).
- Harmless denials (DTrace helper, Rosetta check, syslog socket, notification center, PATH-search stats) are listed with a reason and never suggested for granting.

## Testing hooks

`CRESC_SANDBOX_EXEC` and `CRESC_LOG` replace `sandbox-exec` and `/usr/bin/log` (the tests use fakes). On a Mac, `log` must be `/usr/bin/log`: in zsh a bare `log` is a shell builtin.

## Not in scope

Anything that needs Apple's Endpoint Security entitlement: live allow/deny of arbitrary running processes and a system extension of our own. The existing extension code in this repository is not used by cresc.

## Known gaps

- File operations in grants rely on the same last-rule-wins behaviour that was measured for network rules; `make probe-sandbox-net` covers networking only.
- Unix-socket grants (`remote unix-socket`) have unverified syntax and always require confirmation.
- The format of network denial lines in the log has not been observed yet; such lines are parsed generically (`host:port` or a socket path).
