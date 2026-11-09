![Cover](assets/cover.png)

# Crescendo (fsCrescendo fork)

**See what programs do to your files, in real time, on a normal Mac, then confine them.**
A local inspector for file activity (created, deleted, modified, renamed, attribute changes, with the process responsible) and a
workbench for `sandbox-exec` profiles: run a suspicious program in a sandbox, see what it was denied, allow only what it needs, restart.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/hero-dark.png">
  <img alt="File activity in the main window" src="docs/screenshots/hero-light.png">
</picture>

- **No Apple entitlement and no SIP changes.** Events come from Apple's own `eslogger` tool through a small helper daemon you
  install once with an administrator password. (The original Endpoint Security app needs an Apple-approved entitlement or a VM with SIP off.)
- **Everything stays on your Mac.** No network access, no telemetry. See [Privacy and permissions](#privacy-and-permissions).
- Fork of [SuprHackerSteve/Crescendo](https://github.com/SuprHackerSteve/Crescendo) (MIT). The original system-extension code is kept
  in the repository but is not part of the "lite" build described here.

## What you can do

| I want to... | Use | Guide |
|---|---|---|
| watch file changes live, with the responsible process | main window, **File** segment | [User guide: Files view](docs/user-guide.md#the-files-view) |
| narrow it down (by path, process, user, kind) and hide noisy folders | **Filter** panel, Delete key, right-click | [Filter and hide](docs/user-guide.md#filter-hide-and-the-row-menu) |
| see the activity as a tree or a picture | **Tree** and **Graph** (horizontal tree or sunburst) | [Tree and Graph](docs/user-guide.md#tree-and-graph) |
| save an episode and replay it later, or send it to someone | **Record** (with pre-roll), **Open Recording...** | [Recordings](docs/user-guide.md#recordings-and-the-player) |
| run an unknown program in a sandbox and loosen it step by step | **Cresc Console**: Sessions, Denials, Profile | [Cresc Console](docs/user-guide.md#the-cresc-console) |
| hand over proof of what a run did | **Export evidence...** (zip with hashes) | [Evidence bundles](docs/user-guide.md#evidence-bundles) |
| script all of it | `python3 -m cresc ...` | [Command line](docs/user-guide.md#command-line) |

Every feature with its location, requirements and verification status: [docs/features.md](docs/features.md).

## Requirements

- macOS 13 (Ventura) or later, Apple silicon or Intel.
- Python 3 for the bundled engine (the Command Line Tools provide `/usr/bin/python3`; Homebrew works too). The engine uses only the standard library.
- An administrator password once (to install the event daemon) and Full Disk Access for that daemon.
- To build from source: Xcode 15 or later (`make doctor` checks).

## Install

**From a release** (recommended): download `Crescendo-lite-*.zip` from the [Releases](../../releases) page, unzip, move **Crescendo.app** to
`/Applications`. The app is signed ad-hoc and **not notarized**, so macOS blocks the first launch: right-click the app, **Open**, **Open**
(or `xattr -dr com.apple.quarantine /Applications/Crescendo.app`). Check the download with `shasum -a 256 -c SHA256SUMS`.

**From source:**

```bash
git clone <URL from the green Code button above> fsCrescendo && cd fsCrescendo
make doctor          # what is installed / missing
make build-lite      # builds build/lite/Crescendo.app (ad-hoc signed, no entitlements)
open build/lite/Crescendo.app
```

## First run (4 steps)

1. Open the app. Click the **File** segment, then **Start**.
2. A banner says the **event daemon** is missing: click **Install daemon...** and enter your administrator password.
3. A second banner asks for **Full Disk Access**: click **Open Full Disk Access...**, drag the highlighted
   `com.loff.crescendo.esd` file into the list (or use the **+** button) and switch it on.
4. Come back to the app and press **Start** again. Rows appear as soon as anything on the Mac changes a file.

If something does not work, see [docs/troubleshooting.md](docs/troubleshooting.md).

## The cresc engine and the command line

The app is a front end for `cresc`, a standard-library Python tool that also works on its own, for example to replay a recording or
watch events in a terminal:

```bash
python3 -m cresc watch --files --cleanup prune < capture.jsonl     # file changes from eslogger output
python3 -m cresc recording info  ~/Library/Application\ Support/Crescendo/Recordings/Files*.crescrec
python3 -m cresc loop demo --target ./the-binary --write-dir ~/.local/state/crescendo/sandbox -- --its-flags
```

Reference: [tools/cresc/README.md](tools/cresc/README.md) (commands) and [tools/cresc/PROTOCOL.md](tools/cresc/PROTOCOL.md) (the JSON-lines interface the app uses).

## Privacy and permissions

- The event daemon runs as root, but only starts `/usr/bin/eslogger` when the app asks, serves **only your user** over a `0600` socket,
  and stops it when you disconnect. Details and uninstall steps: [SECURITY.md](SECURITY.md).
- Recordings and evidence bundles contain file paths and process names. Your home folder path is replaced by `~` when you export evidence
  (unless you turn that off); other personal data is not removed, so look before you share.
- Nothing is sent anywhere. The app and engine open no network connections.

## Status and limits

- The **lite build** shows live data in the **File** segment (and in the Cresc Console). The other segments of the main window
  (All Events, Process, Network, Unsigned, Exclude Apple) belong to the original Endpoint Security app and stay empty in the lite build.
- Events are notifications: you can watch, but not block file operations (blocking needs the Apple-approved Endpoint Security entitlement).
- Feature-by-feature verification status (verified on a Mac / implemented, awaiting a first test): [docs/features.md](docs/features.md).

## Documentation

[docs/README.md](docs/README.md) lists everything: [User guide](docs/user-guide.md), [Features](docs/features.md),
[Troubleshooting](docs/troubleshooting.md), [Development](docs/development.md), [Event daemon](docs/event-daemon.md),
[Recording format](docs/recording-format.md), [Sandbox semantics](docs/sandbox-semantics.md).

## Credits and licence

MIT licence ([LICENSE](LICENSE)). Original Crescendo by Stephen Davis (FireEye, Inc.). This fork adds the lite build, the event daemon,
the `cresc` engine, the Cresc Console and the Files view.
