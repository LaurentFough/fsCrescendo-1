#= cresc  version 0.3.0 (2026-11-07)
#= Sandbox-denial triage, rule synthesis, profile versioning and managed sessions for macOS.
#= Standard library only; Python 3.9+. Everything outside session.py is pure logic and testable on any OS.
#= Out of scope on purpose: anything that needs Apple's Endpoint Security entitlement.
__version__ = "0.4.0"

#= JSON schemas emitted by the CLI (the contract a GUI can rely on)
SCHEMAS = {
    "denials": "cresc.denials/1",
    "triage": "cresc.triage/1",
    "profile": "cresc.profile/1",
    "run": "cresc.run/1",
    "event": "cresc.event/1",
    "bundle": "cresc.bundle/1",
}
