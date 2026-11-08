#!/bin/sh
#= esd-sign.sh  version 1.0.0 (2026-11-08)
#= Signs the event-daemon binary AS YOUR USER (root cannot see your login keychain), with a fixed identifier.
#= Why  : macOS keys a Full Disk Access grant to the code's signing requirement. An ad-hoc signature (identity "-") has
#=        a new hash on every build, so the grant is lost on every rebuild. A real certificate (an Apple Development
#=        identity from Xcode, free or paid, or your own local self-signed one) gives a requirement that survives
#=        rebuilds. The identity is read from SIGN_IDENTITY; it is never written to the repository.
#= Usage: SIGN_IDENTITY=-|auto|"<name or SHA-1>" esd-sign.sh BINARY
#=        auto = the first "Apple Development" identity from `security find-identity -v -p codesigning`
#= Exit : 0 ok | 64 usage | 66 missing input | 70 signing failed
set -eu

VERSION="1.0.0"
IDENTIFIER="com.loff.crescendo.esd"
log() { printf '%s esd-sign[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

[ $# -eq 1 ] || die "usage: SIGN_IDENTITY=... $0 BINARY" 64
BIN=$1
[ -f "$BIN" ] || die "binary not found: $BIN (run: make esd-build)" 66
command -v codesign >/dev/null 2>&1 || die "codesign not found (macOS only)" 66
ID=${SIGN_IDENTITY:--}

if [ "$ID" = auto ]; then
  ID=$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/^ *[0-9]*) \([0-9A-F]\{40\}\) "Apple Development:.*/\1/p' | head -n 1)
  [ -n "$ID" ] || die "no 'Apple Development' identity found. Open Xcode > Settings > Accounts, add your Apple ID, Manage Certificates > +, or use make esd-identities" 66
  log "auto-selected identity $ID"
fi

codesign --force --sign "$ID" --identifier "$IDENTIFIER" --timestamp=none "$BIN" || die "codesign failed (identity: $ID)"
codesign --verify --strict "$BIN" || die "verification failed: $BIN"
info=$(codesign -dv "$BIN" 2>&1 | sed -n 's/^Signature=/signature: /p;s/^TeamIdentifier=/team: /p;s/^Identifier=/identifier: /p' | tr '\n' ' ')
log "signed $BIN ($info)"
if [ "$ID" = "-" ]; then
  log "ad-hoc: Full Disk Access will be forgotten after each rebuild. For a stable grant: SIGN_IDENTITY=auto (see docs/event-daemon.md)"
fi
