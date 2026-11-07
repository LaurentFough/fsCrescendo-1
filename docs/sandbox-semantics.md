---
title: "Measured sandbox-exec network rule semantics (macOS 27.2)"
description: "What sandbox-exec actually does with outbound-network rules on macOS 27.2 arm64, measured with scripts/probe-sandbox-net.sh, and what that means for generating sandbox profiles."
slug: sandbox-exec-network-semantics-macos-27
author: "Clauiri (Claude Code session) for the repository owner"
type: reference
date-created: 2026-11-07
date-modified: 2026-11-07
date-published:
source: "scripts/probe-sandbox-net.sh v1.1.0, run by the repository owner on macOS 27.2 (build 26B123), arm64"
domain: macos-security
url:
draft: true
tags:
  - macos
  - sandbox-exec
  - seatbelt
  - sbpl
  - network
keywords:
  - sandbox-exec
  - SBPL
  - network-outbound
  - rule order
---

# Measured `sandbox-exec` network rule semantics

Measured, not documented: Apple does not publish SBPL documentation, and community sources disagree. These results come from `scripts/probe-sandbox-net.sh` v1.1.0 (`make probe-sandbox-net`), which runs `curl` against a throwaway loopback HTTP server under 15 profiles, all with an `(allow default)` base. **Re-run it after major macOS updates.**

## Results

| Case | Profile (after `(version 1)(allow default)`) | Verdict |
|---|---|---|
| C0 | no sandbox | ALLOWED |
| C1 | nothing | ALLOWED |
| C2 | `(deny network-outbound)` | BLOCKED |
| C3 | `(deny network-outbound)(allow network-outbound (remote tcp "localhost:PORT"))` | ALLOWED |
| C4 | `(allow network-outbound (remote tcp "localhost:PORT"))(deny network-outbound)` | ALLOWED |
| C5 | deny, then allow `(remote tcp "*:PORT")` | ALLOWED |
| C6 | deny, then allow `(remote ip "localhost:PORT")` | ALLOWED |
| C7 | deny, then allow `(remote tcp "127.0.0.1:PORT")` | **rejected**: `host must be * or localhost in network address` |
| C8 | `(deny network*)` | BLOCKED |
| F1 | deny, then allow `(remote tcp "*:1")` (wrong port) | BLOCKED |
| G1 | `(deny network-outbound (remote tcp "*:PORT"))` | BLOCKED |
| O1 | deny, filtered allow, then filtered deny (same filter) | BLOCKED |
| O2 | deny, filtered deny, then filtered allow (same filter) | ALLOWED |
| S1 | deny, allow `*:*`, then deny `localhost:PORT` | BLOCKED |
| S2 | deny, deny `localhost:PORT`, then allow `*:*` | ALLOWED |

## What follows

1. **A bare rule (no filter) is the operation's default**, not an ordered rule. A filtered allow beat a bare deny whether it came before or after it (C3, C4).
2. **Among filtered rules the last matching rule wins** (O1/O2), and **specificity does not matter** (S1/S2): a later broad allow overrides an earlier narrow deny.
3. **Filters are real filters.** An allow for the wrong port did not open the right one (F1); a filtered deny blocks by itself (G1).
4. **The remote host can only be `*` or `localhost`** (C7). Numeric IPs and hostnames are rejected on this macOS, so sandbox profiles can restrict network access by **protocol and port only**, never by destination host. Per-host control needs a NetworkExtension filter or the `pf` firewall, outside the sandbox.
5. Accepted forms: `tcp` and `ip` protocols; `localhost:PORT`, `*:PORT`, `*:*`.

## Rules for generating profiles

- Start from a default deny; add **filtered allows**. They work wherever they are placed.
- Put an exception (a deny that must override an earlier allow) **after** that allow.
- Network grants are protocol plus port. Never suggest `*:*` automatically; require explicit confirmation.
- Do not rely on community examples that name hosts (`"example.com:443"`); they are invalid here.

## Not verified yet

- File operations and Mach lookups probably share the engine but were not measured.
- UDP, Unix-socket (`remote unix-socket`) and inbound rules.
- The format of **network denial lines** in the unified log: the probe found no `Sandbox` lines for `curl` in `log show` (`make logs-sandbox` is the way to watch live).
- A `(deny default)` base with these rules (our current profile uses one and works in practice).

## References

```bibtex
@manual{apple_sandbox_exec_man,
  title        = {sandbox-exec(1) manual page},
  organization = {Apple Inc.},
  howpublished = {macOS man pages (\texttt{man sandbox-exec})},
  note         = {Deprecated, still shipped}
}
@online{sbpl_description,
  title = {Description of the SBPL - The Apple SandBox Policy Language},
  url   = {https://romab.com/ironsuite/SBPL.html},
  note  = {Community reverse-engineering; no official SBPL documentation exists}
}
```
