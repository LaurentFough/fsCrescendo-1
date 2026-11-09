---
title: "Plan: FSMonitor-style file activity in the main Crescendo window"
description: "Review of the FSMonitor feature set against what Crescendo already has, a data and source design, phased plan, risks and open decisions."
slug: plan-file-activity-view
author: "Clauiri (Claude Code session) for the repository owner"
type: plan
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "FSMonitor site, documentation and four screenshots supplied by the owner; fixtures in tools/cresc/tests/fixtures"
domain: macos-security
url:
draft: true
tags:
  - plan
  - file-activity
keywords:
  - FSMonitor
  - eslogger
  - main window
---

# Plan: FSMonitor-style file activity in the main Crescendo window

Status: **proposal for discussion, nothing implemented.**

## 1. What FSMonitor shows (from the screenshots)
| Area | Observed |
|---|---|
| Toolbar | record/pause (Space), clear (with dropdown: discard options), filter toggle (with dropdown), view modes tree / list / text, inspector toggle |
| List view | columns Kind (icon), PID, Process, Path (with file icon, red cross if deleted), Inode, Date; legend bar |
| Text view | monospaced lines `Date  Cat  PID  Process Name  Inode  Path`, deleted/moved rows coloured, selection highlighted |
| Filter | predicate rows ("All of the following are true", `Process Name` `contains` `cfprefsd`), `Apply Filter Template`, `Save as Template...`, cleanup popup ("No Cleanup"), "Permanently Discard Events" |
| Inspector | Current Status (icon, path, created, modified); Event Information (category, event type, date/time, UID, GID, mode, inode, device, source path of a move); Process Information (PID, PPID, path, ...); Session information |
| Tree view | node-link tree of changed paths, badge = number of events per file, red cross = last event removed it |
| Categories | Created, Deleted, Content Modified, Attributes Modified, Moved From, Moved To, Meta Event (start/stop markers) |
| Output | save/reopen recordings as documents, export JSON or plain text, `fsmon` command-line tool |

Observations that matter for design (inference from the screenshots, not stated by the vendor): paths carry the
`/System/Volumes/Data` prefix; attribute changes sometimes show `kernel_task` (pid 0); event names such as "Item Renamed" and
"Xattrs Changed" match FSEvents flag names. This suggests a lower-level FSEvents-style source, not Endpoint Security.

## 2. What we already have
- Event source: `crescendo-esd` -> `eslogger` -> `cresc serve` (`watch.start`) -> `cresc.event/1`, scoped and filtered.
- **Real `eslogger` events contain a full `stat` for every file** (inode, device, mode, uid, gid, birth/ctime), and the
  acting process (pid, ppid, path, signing id, responsible process) is captured at event time, so we do not lose the
  process when it exits (FSMonitor can).
- Gaps in our parser: `stat` is not extracted yet; create/rename to a NEW path, `unlink`, attribute events are not
  validated on real data; no "category" model; no pruning; no recording format; the main window is the old ES-extension UI.

## 3. Design
### 3.1 Source
Primary: eslogger via the daemon. Subscribe only to file-change events (not every open/read):
`create rename unlink close truncate link clone exchangedata setattrlist setmode setowner setflags setextattr deleteextattr setacl utimes write`
(`close` with `modified=true` gives one "content modified" per file instead of one per write; `write` is optional).
Later, optional light mode: public FSEvents API (no root, no process attribution).

### 3.2 Normalised record `cresc.filechange/1` (engine, pure logic, tested on Linux)
`{ts, seq, category, event_type, path, source_path, inode, device, mode, uid, gid, created, modified, process{pid, ppid, name, path, signing_id, uid, gid}}`
- category: created | deleted | modified | attributes | moved_from | moved_to | meta
- rename -> two records (moved_from with source, moved_to), like FSMonitor
- path normalisation: one canonical form (strip or add `/System/Volumes/Data`), configurable
- mute list for the tooling's own noise (eslogger, crescendo-esd, cresc, mds, fseventsd, ...)

### 3.3 Cleanup ("pruning") modes (engine, pure, tested)
- none
- prune transient: create followed by delete of the same inode/path inside a window disappears
- coalesce: repeated modified/attributes events for one path collapse to one with a count
- atomic save: write temp file + rename over target = one `modified` of the target (the `cfprefsd` pattern in the screenshots)

### 3.4 Recordings
Header line (session: host name, macOS version, tool versions, scope, filter, start/stop times) followed by `cresc.filechange/1`
lines (`.crescrec`, plain JSON lines, human-readable). Methods: `recording.save`, `recording.open`, `recording.export`
(json, text, csv). Evidence bundles reuse it as `events/` (resolves the parked "attach events" item).

### 3.5 App (main window)
- A programmatic Files UI inside the main window (same approach as the console: split views, tooltips, list rows),
  fed by an `EventSource` abstraction: engine source (lite build) and the original extension source (full build).
- List view with the FSMonitor columns, legend bar, Space = record/pause, clear, cleanup popup, "permanently discard".
- Filter: `NSPredicateEditor` rows (path / process name / category / pid / uid) + saved templates (UserDefaults, JSON export).
- Inspector panel (right, toggled) and the already-resizable details area.
- Text view (copyable), tree view (outline with counts) later, graph visualisation last.

## 4. Phases
| Phase | Scope | Testable where |
|---|---|---|
| P0 | real captures for create/rename/unlink/attrs (also closes the parked step 2); extract `stat`; fixtures | Mac, then Linux tests |
| P1 | `filechange` model, category mapping, rename pairs, normalisation, mute, tests; `watch.start view=files` pushes `watch.change` | Linux |
| P2 | cleanup/pruning engine + tests; `cresc watch --files` CLI (parity with `fsmon`) | Linux |
| P3 | main window list + text view, legend, record/pause, clear, inspector (read-only) | Mac |
| P4 | filter predicate editor + templates; hide-directory key; cleanup popup wired | Mac |
| P5 | recordings (save/open/export JSON/text/CSV), session info; evidence bundle events | Linux + Mac |
| P6 | tree view (outline with counts) | Mac |
| P7 | graph visualisation (screenshot 3): native drawing or bundled web view | Mac |
| P8 | optional FSEvents light mode (no root) | Mac |

## 5. Risks
- **Volume**: file events are bursty; the table needs batching, a bigger ring buffer or virtual rows, and engine-side filtering.
- **Fidelity**: "modified" via `close` misses a file still open for writing; atomic-save patterns need the pruning rules.
- **Unvalidated parsers**: create/rename to a new path, unlink details, xattr events (P0 captures them).
- **Layout**: the main window is a storyboard with fixed frames; adding an inspector at runtime is fragile (see decision 1).
- **Privacy**: recordings contain paths and process names; redaction as in evidence bundles.

## 6. Decisions to discuss
1. Main window UI: patch the storyboard, or host a new programmatic Files view and keep the old controller for the full build?
2. Is eslogger-via-daemon the primary source, with FSEvents as an optional no-root mode later?
3. Recordings: simple Save/Open of `.crescrec` files first, real `NSDocument` later?
4. Visualisation technology: native drawing, or a bundled web view?
5. Keep the existing segments (All Events, File, Process, Network, Unsigned, Exclude Apple) and give File the new look?
6. Process/Network panes: unchanged for now?
