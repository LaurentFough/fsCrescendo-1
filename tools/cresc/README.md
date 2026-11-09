---
title: "cresc: sandbox-denial triage and managed sandbox sessions"
description: "Engine for the local inspector: runs a program under a versioned deny-default sandbox profile, collects its Seatbelt denials, suggests allow rules, and restarts it under the updated profile."
slug: cresc-readme
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-07
date-modified: 2026-11-07
date-published:
source: "tools/cresc, version 0.3.0"
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

*Renamed from `fsx` in 0.2.0.* Data lives in `~/.local/share/crescendo/cresc` (override: `CRESC_HOME`). Data in the older locations `~/.local/share/cresc` and `~/.local/share/fsx` is moved there automatically on first use (one rename; if that is impossible the old folder is used in place). The `FSX_HOME` variable is still honoured. The test hooks are now `CRESC_LOG` and `CRESC_SANDBOX_EXEC`.

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
python3 -m cresc loop demo --target ./the-binary --write-dir ~/.local/state/crescendo/sandbox -- --its-flags
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
| `cresc output NAME [--run N] [--bytes B] [--json]` | the run's arguments, exit status, stdout and stderr (control characters escaped) |
| `cresc loop NAME ...` | interactive run / grant / restart |
| `cresc export NAME [--run N] [-o FILE.zip] [--events FILE] [--no-redact]` | evidence bundle of one run: record, output, denials, analysis, profile, SHA-256 manifest (`cresc.bundle/1`) |
| `cresc verify-bundle FILE.zip` | check a bundle against its manifest (exit 1 on any difference) |
| `cresc serve` | JSON-lines interface on stdin/stdout for a GUI, see [PROTOCOL.md](PROTOCOL.md) |
| `cresc watch --files [--cleanup none\|coalesce\|prune] [--cleanup-window S]` | file-change view (created / deleted / modified / attributes / moved) of `eslogger create rename unlink close ...` input; `prune` hides temp files and collapses atomic saves (`cresc.filechange/1` with `--json`) |
| `cresc watch [FILE|-] [--app/--dir/--file/--pid ...]` | live or replayed event view from `eslogger` JSON (`--json`: `cresc.event/1`) |

Program arguments go after a literal `--`. Data lives in `$CRESC_HOME` (default `~/.local/share/crescendo/cresc`).

## Watching events (`cresc watch`)

Shows what programs do on the machine, from Apple's own `eslogger` (macOS 13+). Only `eslogger` runs as root; cresc just reads
its JSON from a pipe or a file, so cresc itself never needs privileges and never needs Apple's Endpoint Security entitlement.
The terminal running `eslogger` needs Full Disk Access.

```bash
# everything visible (noisy Spotlight/logging daemons are hidden by default; --no-mute shows them)
sudo eslogger exec fork exit open close write create rename unlink | python3 -m cresc watch -

# narrow to one app and its children, a folder, a file, or a pid; denials from the sandbox join the same timeline
sudo eslogger exec fork exit open close write create rename unlink | \
  python3 -m cresc watch --app thebinary64 --denials thebinary64 -
sudo eslogger open close write create rename unlink | python3 -m cresc watch --dir ~/Library/Application\ Support/x --json -
```

- Scopes combine with OR: `--app NAME|PATH|SIGNING_ID` (children and processes macOS holds responsible to the app are followed, `--no-follow` disables that), `--dir PATH`
  (paths are matched on directory boundaries, so `/a/out2` is not under `/a/out`), `--file PATH`, `--pid N`.
- `--kinds 'file.*,proc.exec'` filters by event kind; `--json` prints one `cresc.event/1` object per line; `--limit N` stops early.
- Filtering is done by cresc after `eslogger` delivers an event (`eslogger` has no kernel-side filter), so a very busy system can drop
  events: gaps in the global sequence number are counted and reported when the stream ends.
- Everything shown comes from files and programs you do not trust and is escaped before printing.
- Pid tracking depends on the fork/exec/exit events it sees; pids are reused, so a followed pid is forgotten when it exits.
- The test fixture (`tests/fixtures/eslogger-sample.jsonl`) is **synthetic**, built from the documented Endpoint Security JSON layout.
  Replace it with a real capture to validate the parser on your macOS version.

## Safety rules built in

- The program starts **inside its first write directory**, never in the directory you launched cresc from, and receives only a
  safe set of environment variables (`PATH HOME USER LOGNAME LANG LC_ALL LC_CTYPE TERM TMPDIR TZ`). Tokens and API keys in your
  shell stay out of its reach; add variables with `--pass-env NAME`, or everything with `--inherit-env`. Run records list
  variable names only, never values.
- Write directories must be absolute and not symlinks; `/`, `$HOME` and its ancestors are refused; directories cresc creates get mode 700, existing ones are not touched.
- Generated rules are **allows only**; strings are escaped and control characters refused; a profile that does not parse is never saved.
- Grants that need confirmation are all-or-nothing: if any selected rule needs `--confirm` and it is missing, nothing is granted.
- Program output is untrusted: it is escaped before it is printed (ESC, NUL, DEL and the C1 range show as `\xNN`), so a suspect
  binary cannot rewrite your terminal or window title.
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
