---
title: "Crescendo user guide"
description: "How to install, set up and use the Crescendo app and the cresc engine: the Files view, filters, recordings, the Cresc Console, evidence bundles and the command line."
slug: crescendo-user-guide
author: "Clauiri (Claude Code session) for the repository owner"
type: how-to
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "the current branch (docs/features.md says what has been verified on a Mac)"
domain: macos-security
url:
draft: false
tags:
  - guide
  - macos
keywords:
  - Crescendo
  - file activity
  - sandbox-exec
---

# Crescendo user guide

Contents: [Set up](#set-up) | [The main window](#the-main-window) | [The Files view](#the-files-view) |
[Filter, hide and the row menu](#filter-hide-and-the-row-menu) | [Tree and Graph](#tree-and-graph) |
[Recordings and the player](#recordings-and-the-player) | [The Cresc Console](#the-cresc-console) |
[Evidence bundles](#evidence-bundles) | [Command line](#command-line) | [Where things are stored](#where-things-are-stored) |
[Keyboard and mouse](#keyboard-and-mouse) | [Uninstall](#uninstall)

## Set up

1. Install the app (README: *Install*). Open it; a small icon appears in the menu bar and the main window opens.
2. Live events need the **event daemon**, a helper that runs Apple's `eslogger` for you. Two banners guide you:
   - *"The event daemon is not installed"*: click **Install daemon...** and enter your administrator password (once).
   - *"The daemon needs Full Disk Access"*: click **Open Full Disk Access...**, drag `com.loff.crescendo.esd` from the Finder window that opens into
     System Settings > Privacy & Security > Full Disk Access, and switch it on.
   The banners appear in the Files view and in the Cresc Console's **Events** tab, and disappear when everything is in place.

![The event daemon setup banner](screenshots/setup-banner.png)
3. From source builds you can also install from a terminal: `make esd-install` (and `make esd-status`, `make esd-log`, `make esd-remove`).
   With `SIGN_IDENTITY=auto` the Full Disk Access grant survives rebuilds (see [event-daemon.md](event-daemon.md)).

## The main window

The menu bar icon's menu shows the build you run (version, build number, commit, time), **Cresc Console...**, **Open Recording...**,
Show App Window, Run in Background / Dock, Quit.

![The menu bar icon's menu](screenshots/menu-bar.png)

The toolbar has **Start / Stop**, **Clear**, a save button, **Auto-scroll**, a search field, **Settings**, and six segments:
**All Events | File | Process | Network | Unsigned | Exclude Apple**.

> In the lite build only **File** shows live data. The other five segments are the original Endpoint Security views; they need the original
> system extension and stay empty. Start/Stop, Clear, search and the save button act on the **File** view while File is selected.

## The Files view

Select **File**, press **Start**. Rows appear as files are created, deleted, modified, renamed or have their attributes changed.

| Control | What it does |
|---|---|
| **List / Text / Tree / Graph** | four ways to see the same rows (below) |
| **Cleanup** | *No Cleanup*: every change. *Coalesce Repeats*: repeated modifications of a file become one row. *Prune Redundant Events*: also hides temporary files and turns write-temp-then-rename saves into one row. Cleaned rows appear about 2 s late |
| **Pause / Resume** | stops capturing (the helper stops `eslogger` too) and resumes; **Space** does the same while the list has focus |
| **Record** and its **pre-roll** menu | save the activity as a recording (see Recordings) |
| **Filter** | opens the filter rules |
| **Inspector** | shows or hides the details panel on the right |

**List**: one row per change with *Kind* (icon: created, deleted, content modified, attributes modified, moved from, moved to, meta), *PID*,
*Process*, *Path* (with the Finder icon of the file type; a red cross for deleted files), *Inode* and *Date* (local time). The legend under the list
explains the icons. **Text**: the same rows as selectable text (date, kind tag, pid, process, inode, path). Both follow **Auto-scroll**.

![The Files view in List mode](screenshots/files-list.png)

**Inspector** (select a row): the file (path, created, modified, owner, mode, size, inode, device, source of a move) and the process
(pid, ppid, path, signing id, uid, gid), with a large file-type icon on top. In Tree and Graph it shows an *activity summary* of the selected path.

Markers *Recording started / stopped* show where a capture began and ended.

![Text mode](screenshots/files-text.png)

## Filter, hide and the row menu

- **Filter** checkbox: *Match All / Any of the following rules*. Each rule is **field, operator, value**. Fields: Path, Process Name, Process Path,
  PID, Category, Event Type, Signing ID, File Owner (uid), Process User (uid). Operators fit the field (contains, is, begins with, greater than...).
  The list follows every keystroke; empty values are ignored. **Apply Filter Template** applies a saved filter; **Save Current Filter as Template...**
  and **Delete a Template...** manage them.
- **Hide a folder**: select rows and press **Delete**: everything under the selected rows' folders disappears. **Command-Delete** brings back the
  last one; the filter panel lists hidden folders with **Restore All**.
- **Right-click a row**: Reveal in Finder, Copy Path, Show Only / Hide this process, Show Only / Hide this folder (these add rules or hidden folders).
- The toolbar **search** field filters on top of all this.

![The filter panel with rules and the template menu](screenshots/files-filter.png)

## Tree and Graph

**Tree**: changed paths as a folder hierarchy. Columns: Changes (everything below), Created, Deleted, Modified, Attr., Moved, Last Change. Buttons
Expand All / Collapse All; sort by name, most recent or most active. Delete hides the selected folder.

![Tree mode with change counts](screenshots/files-tree.png)

**Graph**: a drawing of the same data.
- **Horizontal Tree**: root left, branches right; files show an orange badge with their number of changes, deleted files a red cross.
- **Sunburst**: one ring per folder level; an arc's angle is its share of all changes below that path; the centre shows the total.
- **Scale**: by default the graph shows the *busiest 200 paths*, *only your own processes*, and hides *Apple system processes* (programs signed by the
  operating system). Each can be changed in the graph toolbar; the status line always says how much is hidden.

![The graph toolbar: layout, caps, filters, zoom](screenshots/graph-controls.png)
- **Navigate**: drag to pan, pinch (or Command/Option + scroll) to zoom at the pointer, double-click to zoom in (Option: out); buttons `-` `+` Fit 100% Center;
  keys arrows / `+` `-` `0` `F` `C`. **Save Image...** writes a PNG.

![Graph: horizontal tree with badges and a deleted file](screenshots/files-graph-tree.png)

![Graph: sunburst](screenshots/files-graph-sunburst.png)

## Recordings and the player

- Press **Record** while capturing. Choose a **pre-roll** first to include the last 1, 5, 15 or 60 minutes already captured. **Stop Recording** saves
  `Files <date>.crescrec` in `~/Library/Application Support/Crescendo/Recordings/` and opens it in a player window.

![The Record button and the pre-roll menu](screenshots/files-record.png)
- **Open Recording...** (File menu, Command-O, the menu bar icon, or double-click a `.crescrec` in the Finder).
- The **player window** has the same List / Text / Tree / Graph, filters and inspector, plus **Play / Pause, Restart, speed** (0.5x to 500x; quiet gaps over
  2 s are shortened), a **time scrubber** (release it to jump: the list shows everything up to that moment) and **Follow newest**. The header says whether the file's
  hash is intact. **Save As...** copies the recording.

![A recording open in the player window](screenshots/player.png)
- Format, verification and command-line tools: [recording-format.md](recording-format.md).

## The Cresc Console

Open it from the menu bar icon: **Cresc Console...**. It runs programs under a sandbox profile and helps you loosen the profile until the program works.

**Sessions**: *Profile* (pick or type a name), *Program* (Choose...), *Write folders* (rows: Add..., +, -, or drag folders in; the first is the working
directory), *Arguments* (one per row). **Start / Stop / Restart**. The program starts with an empty environment, no stdin, inside the sandbox; everything
outside the write folders is read-only or denied.

![Cresc Console: Sessions](screenshots/console-sessions.png)

**Denials**: pick a run; **Candidates | All**; search. Columns: Change (new / persisting vs the previous run), Class, Risk, Process, Operation, Target, Count, Rule.
The detail box explains the selected row. Buttons: **Grant selected**, **Grant selected & restart**, **Grant all low-risk**, **Grant up to medium...**,
**Add rule by hand...** (high-risk or unverified rules ask for confirmation). The workflow: run, review, grant, restart, compare.

![Cresc Console: Denials](screenshots/console-denials.png)

**Profile**: the history of every change, the sandbox text of the selected version, **Diff with previous**, **Revoke selected grant**.

![Cresc Console: Profile](screenshots/console-profile.png)

**Events**: a raw event view with scope (all / app / dir / file / pid), kinds and pause, using the same daemon.

![Cresc Console: Events](screenshots/console-events.png)

## Evidence bundles

On the Denials tab: **Export evidence...** writes a zip for the shown run: run record, program output (control characters escaped), denials, analysis,
the exact sandbox profile used, and a manifest with SHA-256 of every file. **Verify bundle...** checks one. A checkbox replaces your home folder path by `~`.
The hash is inside the zip: it shows the files were not changed afterwards, not who wrote them. Keep the zip's own SHA-256 elsewhere if it is evidence.

## Command line

`python3 -m cresc <command>` (from `tools/cresc`, or from the release's `cresc-engine` folder). Main commands: `watch` (live or replayed events, `--files`, `--cleanup`),
`recording info|verify|export|play`, `profile`, `run`, `loop` (interactive grant-and-restart), `triage`, `export`, `verify-bundle`, `serve` (the app's interface).
Full list: [tools/cresc/README.md](../tools/cresc/README.md).

## Where things are stored

| What | Where |
|---|---|
| profiles and runs | `~/.local/share/crescendo/cresc` (`CRESC_HOME` overrides; older folders are moved here automatically) |
| default sandbox write folder | `~/.local/state/crescendo/sandbox`, else `~/Library/Application Support/Crescendo/sandbox` |
| recordings | `~/Library/Application Support/Crescendo/Recordings/` |
| event daemon (installed) | `/Library/PrivilegedHelperTools/com.loff.crescendo.esd`, `/Library/LaunchDaemons/com.loff.crescendo.esd.plist` |
| daemon socket and log | `/var/run/com.loff.crescendo.esd.sock` (owned by you, mode 0600), `/var/log/crescendo-esd.log` |
| app preferences | the app's preferences domain (filter templates, graph settings, last console values) |

## Keyboard and mouse

| Where | Keys |
|---|---|
| Files list | **Space** pause/resume; **Delete** hide folder; **Command-Delete** restore; right-click menu |
| Tree | **Delete** / **Command-Delete** as above |
| Graph | arrows pan; `+` `-` zoom; `0` actual size; `F` fit; `C` centre; drag pans; double-click zooms |
| Anywhere | **Command-O** Open Recording... |

## Uninstall

1. Quit the app and delete `Crescendo.app`.
2. Remove the daemon: `make esd-remove` from a source checkout, or `sudo sh scripts/esd-install.sh remove`. Remove it from Full Disk Access too.
3. Optional: delete the folders in *Where things are stored*.
