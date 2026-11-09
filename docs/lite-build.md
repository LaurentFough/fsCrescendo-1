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

## Resizable details (v0.4)
- Console **Denials** and **Profile** tabs: a draggable divider between the table and the details/sandbox-text area.
- Main window: drag the strip just above "Event Details" up or down. One box serves every filter (All Events, File,
  Process, Network, Unsigned, Exclude Apple). The height is remembered between launches.

## Files view in the main window (P3, first version)
Select the **File** segment: a programmatic Files view replaces the event table and details area (other segments are unchanged).
- Needs the event daemon (`make esd-install`, Full Disk Access): if it is missing, a banner explains and opens the console's Events tab.
- The window's **Start / Stop** capture (live, rolling buffer of the newest 20,000 rows), **Clear** empties the list, the **search**
  field filters the shown rows, the floppy button exports the visible rows as JSON lines (`cresc.filechange/1`).
- **List** (Kind icon, PID, Process, Path, Inode, Date) or **Text** (selectable). **Cleanup** popup: No Cleanup, Coalesce Repeats,
  Prune Redundant Events (cleaned rows appear about 2 s late). **Pause / Resume** (Space while the list has focus).
- Inspector (right): path, created / modified, category, event type, owner, mode, size, inode, device, source of a move,
  process (pid, ppid, path, signing id, uid, gid). Legend bar under the list.

## Files view: filter, hidden folders, row menu (P4)
- **Filter** checkbox shows the rules: `Match All / Any of the following rules`, each rule `[field] [operator] [value]` with `-` / `+`.
  Fields: Path, Process Name, Process Path, PID, Category, Event Type, Signing ID, File Owner (uid), Process User (uid).
  The list follows every keystroke; empty values are ignored; start/stop markers are never filtered out. The toolbar search field
  still applies on top.
- **Templates**: *Apply Filter Template* menu, *Save Current Filter as Template...*, *Delete a Template...* (stored in the app's preferences).
- **Delete** hides every change under the folder of the selected rows (a folder row hides itself); **Command-Delete** brings back the folder
  hidden last; the panel lists the hidden folders with *Restore All*.
- **Right-click** a row: Reveal in Finder, Copy Path, Show Only / Hide this process, Show Only / Hide this folder (these add filter rules or hidden folders).

## Recording and replay in the app (P5, app side)
- **Record** (Files view toolbar, enabled while capturing): saves the activity from now on, optionally with a **pre-roll** (the last
  1 / 5 / 15 / 60 minutes already captured) to `~/Library/Application Support/Crescendo/Recordings/Files <date>.crescrec`. **Stop Recording**
  (or ending the capture) finishes the file and opens it in a player window.
- **Open Recording...** (File menu, Command-O; also in the menu bar item; double-clicking a `.crescrec` in the Finder) opens a recording
  as a read-only document. **Save As...** copies the file. The window header says what the recording is and whether its hash is intact.
- **Player window**: the same list / text / inspector / filter / hidden-folder UI as live capture, plus Play / Pause, Restart, speed
  (0.5x to 500x; quiet gaps over 2 s are shortened), a time scrubber (releasing it rebuilds the list up to that moment) and "Follow newest".
- Format and command line: `docs/recording-format.md`, `python3 -m cresc recording info|verify|export|play`.

## Tree view (P6)
The **Tree** segment (next to List and Text) shows the changed paths as a folder hierarchy. It uses the same filtered rows as the list, so the
filter panel and hidden folders apply to it too, and it works the same in the player window.
- **Columns**: Path (Finder icon, red cross when the last change deleted it), Changes (everything at or below the path), Created, Deleted,
  Modified, Attr., Moved, Last Change. Counts roll up through the folders, so busy places stand out.
- **Toolbar**: Expand All, Collapse All, and the order inside folders: by name, most recent first, or most active first. The first two levels
  open by themselves.
- **Selecting** a path fills the inspector with an *activity summary* (counts per kind, first and last change, busiest processes) and, if the
  path itself changed, the details of its latest change.
- **Delete** hides the selected folder, **Command-Delete** brings the last hidden folder back; the right-click menu offers Reveal in Finder,
  Copy Path, Show Only This Folder and Hide This Folder.
