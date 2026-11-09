---
title: "cresc recording format (.crescrec)"
description: "JSON-lines format for saved file activity: header, typed records with relative time, SHA-256 footer; how verification and replay work."
slug: crescrec-format
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "tools/cresc/cresc/recording.py 0.1.0, cresc 0.7.0"
domain: macos-security
url:
draft: true
tags:
  - format
  - recording
keywords:
  - crescrec
  - JSON lines
---

# `.crescrec`

One JSON object per line, UTF-8.

```text
{"schema":"cresc.recording/1","kind":"live-capture","created":"2026-11-09T03:21:36Z","tool_version":"0.7.0","host":{...},"source":{...},"scope":[...],"cleanup":"prune","filters":{...},"notes":""}
{"type":"change","t":0.0,"data":{ ...cresc.filechange/1... }}
{"type":"change","t":0.213,"data":{ ... }}
{"type":"end","records":2,"sha256":"<hex>","ended":"2026-11-09T03:25:00Z","duration_s":0.213,"truncated":false}
```
| Part | Meaning |
|---|---|
| header | session information: kind (`live-capture` or `run-session`), time, tool version, host (system, macOS, machine, Python, host name unless excluded), event source, scope, cleanup mode, filters, notes |
| record `type` | `change` (cresc.filechange/1), `event` (cresc.event/1), `denial`, `run`, `grant`, `note` |
| `t` | seconds since the start of the recording; never decreases; pre-roll rows come first |
| footer | record count and the SHA-256 of every byte before the footer line |

- **Integrity**: `python3 -m cresc recording verify FILE` checks structure, time order, record count and the hash. It is
  tamper-*evident*: the hash lives in the same file, so keep the file's own SHA-256 elsewhere if it is evidence.
- **Incomplete files**: a file without footer (crash, or still `<name>.part`) can be read and replayed; verification reports it as incomplete.
- **Limits**: 5,000,000 records or 2 GiB per recording; lines up to 4 MiB.
- **Replay**: the player pushes records at the recorded cadence (`speed`, `max_gap` shortens long idle gaps), supports pause,
  resume, speed change and seek. A seek first pushes `reset: true` with everything up to that time, so a client can rebuild its table.
- **Export**: `text`, `csv`, `json`, `jsonl`.
- **Privacy**: recordings contain paths and process names; the host name is included unless `include_host` is false.
