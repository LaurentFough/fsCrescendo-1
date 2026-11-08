---
title: "cresc serve: JSON-lines protocol for the GUI"
description: "Reference for the machine-readable interface (protocol 1) that the Crescendo app uses to drive profiles, managed runs, denial triage and event watches."
slug: cresc-serve-protocol
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-08
date-modified: 2026-11-08
date-published:
source: "tools/cresc/cresc/serve.py, protocol 1, cresc 0.4.0"
domain: macos-security
url:
draft: true
tags:
  - macos
  - protocol
  - json
keywords:
  - cresc serve
  - JSON lines
  - sandbox
---

# `cresc serve`: protocol 1

Start it as a child process: `python3 -m cresc serve [--store DIR]`. It reads requests from **stdin** and writes to **stdout**, one JSON object per line. Nothing listens on a network socket. Logs and tracebacks go to **stderr** only. When stdin closes (or `shutdown` is called) it cancels active runs and watches and exits 0.

All output is ASCII-only JSON (non-ASCII is `\uXXXX`-escaped), so one object is always exactly one line.

## Messages

```text
request  : {"id": 1, "method": "run.start", "params": {...}}          id: number or string; params optional
response : {"id": 1, "ok": true,  "result": {...}}
           {"id": 1, "ok": false, "error": {"code": "...", "message": "...", "data": ...}}   data is optional
push     : {"event": "run.denial", "data": {...}}                      no id; may arrive at any time, also between a request and its response
```

A request line may be at most 1 MiB. Anything malformed gets an error response (with `"id": null` when the id could not be read); the server never stops because of a bad request.

### Error codes

| Code | Meaning |
|---|---|
| `parse_error`, `invalid_request` | the line is not JSON / not a request object |
| `unknown_method`, `invalid_params` | no such method / a parameter is missing or has the wrong type or range |
| `not_found` | unknown run, watch, rule id or no active run to stop |
| `profile_error`, `session_error` | profile problems (exists, invalid name, unknown version) / refused to run (bad directory, program not found, ...) |
| `confirmation_required` | a grant needs `confirm: true`; `error.data.rules` lists exactly which rules (`cresc.triage` items) |
| `refused`, `limit`, `too_large`, `timeout`, `internal` | refused by a safety rule / too many watches / request too big / a run did not start / unexpected (see stderr) |

## Methods

Names are letters, digits, `.`, `_`, `-` (profiles). Paths must be absolute. `run` is a positive integer or `"last"`.

| Method | Params | Result |
|---|---|---|
| `hello` | | `protocol`, `cresc`, `schemas`, `methods`, `store`, `limits` |
| `shutdown` | | `{"bye": true}` |
| `profile.list` | | `profiles: [name]` |
| `profile.new` | `name` | `name`, `version` (1) |
| `profile.show` | `name`, `version?` | `version`, `shown_version`, `grants`, `text` (the SBPL) |
| `profile.history` | `name` | `history: [{version, ts, action, grant?, risk?}]` |
| `profile.diff` | `name`, `a`, `b` | `diff` (unified) |
| `profile.grant` | `name`, then at least one of: `ids[]`, `auto` (`"low"`/`"medium"`), `manual[]` (`"OPERATION TARGET"`); source of denials for `ids`/`auto`: `run` (default `"last"`) or `denial_lines[]`; `confirm?`, `note?`, `path?`, `home?` | `version`, `grants: [{id, rule, version, changed}]` |
| `profile.revoke` | `name`, `id` | `version` |
| `triage.run` | `name`, `run?`, `all?`, `path?`, `home?` | `run`, `summary`, `items`, `prefix_suggestions` |
| `triage.lines` | `lines[]`, `all?`, `path?`, `home?` | as `triage.run`, plus `skipped_lines` |
| `run.start` | `name`, `target`, `write_dirs[]` (1-8), `args?`, `watch?[]`, `timeout?`, `settle?`, `startup_wait?`, `pass_env?[]`, `inherit_env?` | `name`, `run`, `profile_version` (returned as soon as the run exists; progress arrives as events) |
| `run.stop` | `name`, `run` | `{"stopping": true}`; the process tree is stopped and `run.finished` follows with `meta.stopped: true` |
| `run.list` / `run.get` | `name` / `name`, `run?` | `runs: [meta]` / `meta`, `triage` |
| `run.output` | `name`, `run?`, `bytes?` | `exit`, `args`, `cwd`, `stdout`, `stderr` (`{bytes, truncated, text}`, control characters escaped) |
| `run.compare` | `name`, `a`, `b` | `resolved`, `new`, `persisting`, `a`, `b` |
| `run.export` | `name`, `run?`, `path?` (absolute `.zip`), `events_file?`, `redact?` (default true), `force?` | `path`, `sha256`, `bytes`, `top`, `files`: an evidence bundle of that run (`cresc.bundle/1`) |
| `bundle.verify` | `path` | `ok`, `checked`, `problems[]` |
| `esd.status` | `socket?` | `available`, and when reachable `state`, `version`, `fda` |
| `watch.start` | `source: {file, follow?}`, `scopes?: [{kind, value}]`, `no_follow?`, `mute?[]`, `no_mute?`, `kinds?[]`, `denials?[]`, `settle?` | `watch_id` |
| `watch.stop` / `watch.stats` | `watch_id` | `stopping` / `running`, `stats` |

`triage` items and rule fields are the `cresc.triage/1` shapes (`class`, `risk`, `needs_confirm`, `rule: {id, text, op, kind, value, verified, confirm, note}`).

### The grant, kill and restart workflow

1. `run.start` -> `run.started`, `run.denial` ... , `run.finished` (with `triage`).
2. Show the candidates. For each rule the user approves: `profile.grant` with `ids`/`auto`/`manual`. If it answers `confirmation_required`, ask about `error.data.rules` and repeat with `confirm: true`.
3. If the program is still running: `run.stop`, wait for `run.finished`.
4. `run.start` again. It uses the profile's new version; `run.compare` shows what was resolved.

### Watching events

The server never runs as root and never starts `eslogger` itself. A privileged helper writes `eslogger` JSON to a file or **FIFO** (`mkfifo`), and `watch.start` reads it: a regular file is replayed to the end (or tailed with `follow: true`); a FIFO stays open until `watch.stop`. Scopes are `{"kind": "app"|"dir"|"file"|"pid", "value": ...}` (paths absolute); at most 4 watches at once.

## Events (push)

| Event | Data |
|---|---|
| `run.started` | `name`, `run`, `profile_version` |
| `run.denial` | `name`, `run`, `denial: {process, pid, op, target, count, ts}` (live, before the run ends) |
| `run.finished` | `name`, `run`, `meta` (`cresc.run/1`: `exit`, `timed_out`, `stopped`, `interrupted`, `duration_s`, `cwd`, `env_names`, ...), `triage` |
| `run.error` | `name`, `run`, `message` |
| `watch.event` | `watch_id`, `event` (`cresc.event/1`; denials appear with `kind: "sandbox.deny"`) |
| `watch.ended` / `watch.error` | `watch_id`, `stats: {read, shown, skipped_lines, dropped, by_kind}` / `message` |

## Example

```text
> {"id":1,"method":"profile.new","params":{"name":"demo"}}
< {"id":1,"ok":true,"result":{"name":"demo","version":1}}
> {"id":2,"method":"run.start","params":{"name":"demo","target":"./tool","write_dirs":["/Users/me/.local/state/crescendo/sandbox"],"args":["-machine"]}}
< {"event":"run.started","data":{"name":"demo","run":1,"profile_version":1}}
< {"id":2,"ok":true,"result":{"name":"demo","run":1,"profile_version":1}}
< {"event":"run.denial","data":{"name":"demo","run":1,"denial":{"process":"tool","pid":4242,"op":"sysctl-read","target":"hw.ncpu","count":1,"ts":null}}}
< {"event":"run.finished","data":{"name":"demo","run":1,"meta":{"exit":0,...},"triage":{"summary":{...},"items":[...]}}}
> {"id":3,"method":"profile.grant","params":{"name":"demo","run":"last","auto":"low"}}
< {"id":3,"ok":true,"result":{"name":"demo","version":2,"grants":[...]}}
```

## Limits and notes

- Events are written as they happen; if the client stops reading, the server blocks on the pipe (back-pressure), so always drain stdout.
- A very busy `eslogger` stream is filtered in user space; use scopes and `kinds` to keep the event rate sane.
- Requests are handled one at a time on the main thread, except that runs and watches work in the background.
