#= fsx  version 0.1.0 (2026-11-07)
#= Sandbox-denial triage, rule synthesis, profile versioning and managed sessions for macOS.
#= Standard library only; Python 3.9+. Everything outside session.py is pure logic and testable on any OS.
#= Out of scope on purpose: anything that needs Apple's Endpoint Security entitlement.
__version__ = "0.1.0"

#= JSON schemas emitted by the CLI (the contract a GUI can rely on)
SCHEMAS = {
    "denials": "fsx.denials/1",
    "triage": "fsx.triage/1",
    "profile": "fsx.profile/1",
    "run": "fsx.run/1",
}
