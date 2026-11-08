#!/bin/sh
#= lite-package.sh  version 1.0.0 (2026-11-08)
#= Turns a built (unsigned) Crescendo.app into the "lite" app: the Endpoint Security system extension is
#= removed and the app is ad-hoc signed ("Sign to Run Locally") with EMPTY entitlements, so it launches on an
#= unmodified Mac (SIP and AMFI on) without any Apple-approved entitlement.
#= Usage : lite-package.sh IN.app OUT.app EMPTY.entitlements
#= Output: OUT.app (IN.app is left untouched). Verifies that no restricted entitlement survives.
#= Exit  : 0 ok | 64 usage | 66 missing input | 70 packaging/signing/verification failed
set -eu

VERSION="1.0.0"
log() { printf '%s lite-package[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

[ $# -eq 3 ] || die "usage: $0 IN.app OUT.app EMPTY.entitlements" 64
IN=$1; OUT=$2; ENT=$3
[ -d "$IN" ]  || die "app bundle not found: $IN (run: make build-xcode SIGN=none)" 66
[ -f "$ENT" ] || die "entitlements not found: $ENT" 66
case "$OUT" in *.app) ;; *) die "OUT must end in .app: $OUT" 64;; esac
[ "$OUT" != "$IN" ] || die "OUT must differ from IN" 64
command -v codesign >/dev/null 2>&1 || die "codesign not found (macOS only)" 66
grep -q 'com.apple.developer' "$ENT" && die "$ENT mentions com.apple.developer: the lite build must stay entitlement-free" 66

#= 1. fresh copy (ditto keeps bundle metadata; cp -R is the fallback)
rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
if command -v ditto >/dev/null 2>&1; then ditto "$IN" "$OUT"; else cp -R "$IN" "$OUT"; fi

#= 2. drop the extension (and the now-empty directory)
if [ -d "$OUT/Contents/Library/SystemExtensions" ]; then
  log "removing embedded system extension(s)"
  rm -rf "$OUT/Contents/Library/SystemExtensions"
fi

#= 3. ad-hoc sign, empty entitlements, no hardened-runtime exceptions needed
codesign --force --deep --sign - --timestamp=none --entitlements "$ENT" "$OUT" || die "codesign failed: $OUT"
codesign --verify --deep --strict "$OUT" || die "verification failed: $OUT"

#= 4. prove it: no restricted entitlement and no extension
ents=$(codesign -d --entitlements :- "$OUT" 2>/dev/null || true)
if printf '%s' "$ents" | grep -q 'com.apple.developer'; then die "restricted entitlement still present in $OUT"; fi
[ ! -e "$OUT/Contents/Library/SystemExtensions" ] || die "system extension still present in $OUT"
log "lite app ready: $OUT"
log "entitlements: none (verified); launches with SIP/AMFI on. No Endpoint Security: events come from cresc/eslogger."
