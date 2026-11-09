---
title: "Crescendo troubleshooting"
description: "Symptoms, causes and fixes for installing, launching and using Crescendo, the event daemon and the cresc engine."
slug: crescendo-troubleshooting
author: "Clauiri (Claude Code session) for the repository owner"
type: how-to
date-created: 2026-11-09
date-modified: 2026-11-09
date-published:
source: "problems met while building and testing the lite build"
domain: macos-security
url:
draft: false
tags:
  - troubleshooting
keywords:
  - Full Disk Access
  - eslogger
  - Gatekeeper
---

# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| macOS says the app is damaged or from an unidentified developer | it is signed ad-hoc and not notarized | right-click the app > **Open** > **Open**, or `xattr -dr com.apple.quarantine /Applications/Crescendo.app` |
| Banner: *event daemon is not installed* | helper not installed | click **Install daemon...** (admin password), or `make esd-install` from a source checkout |
| Banner: *no Full Disk Access* | the daemon needs the permission to run `eslogger` | **Open Full Disk Access...**, drag `/Library/PrivilegedHelperTools/ca.forgeWorx.crescendo.esd` in, switch it on; then press Start again |
| Full Disk Access works, then stops after you rebuild | an ad-hoc signature changes with every build | `make esd-install SIGN_IDENTITY=auto` (an Apple Development identity gives a stable signature) |
| Start does nothing; status says *no event source* | daemon not reachable | `make esd-status` (JSON) and `make esd-log`; reinstall with `make esd-install` |
| *eslogger exited with status ...* in the log | missing Full Disk Access, or a macOS older than 13 | grant Full Disk Access; check `sw_vers` |
| No rows although the daemon is fine | the filter, hidden folders or the search field hide everything | untick **Filter**, press **Restore All**, clear the search field; check the **Graph** status line for hidden rows |
| Rows only for a few processes in the Graph | default graph filters: *only my processes*, *hide Apple system processes* | change them in the graph toolbar |
| Other segments (All Events, Process, Network...) are empty | they belong to the original system extension, absent in the lite build | use **File** and the Cresc Console |
| *python3 not found* in the Console status | no Python 3 | `xcode-select --install` or `brew install python`; or set `CRESC_PYTHON=/path/to/python3` |
| *cresc engine not found* | app moved out of a bundle that contains it, or a dev build outside the repository | use the release app, or set `CRESC_ENGINE_DIR` to the folder that contains the `cresc` package |
| A recording will not open by double-click | the document type is registered when the app is first run from its final location | open it with **File > Open Recording...**; move the app to /Applications and launch it once |
| Player says *NOT VERIFIED* | the file was changed after it was written, or is incomplete | `python3 -m cresc recording verify FILE` lists the problems |
| Sandbox run: *Operation not permitted* for things you allowed | rules apply to the profile *version* used at Start | press **Restart** after granting |
| `make build-lite`: Run Script fails with swiftlint | old project build phase | pull the latest; the phase is non-fatal now |
| `make build-lite`: *requires a provisioning profile* | a restricted entitlement is attached to a signed target | use `make build-lite` (not `build-signed`); the lite app has no entitlements |
| Finder shows an old date for the app | a `.app` folder's date changes only when its direct children change | the packaging step now touches the folder; compare `stat` of the folder and `Contents/MacOS/Crescendo` |

## Collecting information for a bug report

```bash
make version                         # app build number, commit, time
make esd-status                      # daemon state (JSON), fda true/false
make esd-log                         # last lines of /var/log/crescendo-esd.log
python3 -m cresc --version 2>/dev/null; python3 --version
```
Do not post recordings or evidence bundles publicly without reading them first: they contain file paths and process names.
