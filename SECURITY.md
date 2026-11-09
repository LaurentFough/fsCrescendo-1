# Security and privacy

## What runs with which privileges

| Component | Privilege | What it can do |
|---|---|---|
| Crescendo app and `cresc` engine | your user | read files you can read, start sandboxed programs, talk to the daemon |
| **crescendo-esd** (event daemon) | **root**, as a LaunchDaemon | on request, run `/usr/bin/eslogger` and stream its output to **your user only** |

The daemon is idle until the app asks it to start. It accepts only event names made of `a-z` and `_`, runs only the configured `eslogger`,
serves one stream at a time, and stops `eslogger` when the client disconnects. Its socket (`/var/run/ca.forgeWorx.crescendo.esd.sock`) belongs to the
installing user with mode `0600`, and every connection's uid is checked again with `getpeereid()`.

## Known limitation

**Any process running as your user can ask the daemon for events**, which means any program you run can read the system-wide file-event
stream. A check of the client's code signature is a planned improvement. Install the daemon only on machines where that is acceptable, and
remove it (`make esd-remove`) when you do not need it.

## Data handling

- Nothing is sent over the network by the app, the engine or the daemon.
- Recordings (`.crescrec`) and evidence bundles contain file paths, process names and ids. Evidence export replaces your home folder with `~`; other
  personal data is not removed. Read what you share.
- The repository must not contain personal data: `make check-pii` (also run in CI) checks tracked files; `make check-pii HISTORY=1` checks history.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab > *Report a vulnerability*) rather than a public issue. Include the build
number from the menu bar item (or `make version`) and steps to reproduce.
