#!/bin/sh
#= lite-package.sh  version 1.2.0 (2026-11-08)
#= Turns a built (unsigned) Crescendo.app into the "lite" app: the Endpoint Security system extension is
#= removed and the app is ad-hoc signed ("Sign to Run Locally") with EMPTY entitlements, so it launches on an
#= unmodified Mac (SIP and AMFI on) without any Apple-approved entitlement.
#= Usage : lite-package.sh IN.app OUT.app EMPTY.entitlements [ENGINE_DIR [ESD_DIR]]
#=          ENGINE_DIR (the folder holding the `cresc` package, e.g. tools/cresc) is copied to Contents/Resources/cresc-engine
#= Output: OUT.app (IN.app is left untouched). Verifies that no restricted entitlement survives.
#= Exit  : 0 ok | 64 usage | 66 missing input | 70 packaging/signing/verification failed
set -eu

VERSION="1.2.0"
log() { printf '%s lite-package[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

[ $# -ge 3 ] && [ $# -le 5 ] || die "usage: $0 IN.app OUT.app EMPTY.entitlements [ENGINE_DIR [ESD_DIR]]" 64
IN=$1; OUT=$2; ENT=$3; ENGINE=${4:-}; ESDDIR=${5:-}
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

#= 2b. bundle the cresc engine (python sources only: no tests, fixtures, caches) so the signed seal covers it
if [ -n "$ENGINE" ]; then
  [ -f "$ENGINE/cresc/__init__.py" ] || die "not a cresc engine directory: $ENGINE" 66
  DEST="$OUT/Contents/Resources/cresc-engine"
  mkdir -p "$DEST"
  ( cd "$ENGINE" && find cresc -name '*.py' -o -name '*.sb' | grep -v __pycache__ ) | while IFS= read -r f; do
    mkdir -p "$DEST/$(dirname "$f")"
    cp "$ENGINE/$f" "$DEST/$f"
  done
  log "bundled engine: $DEST ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
fi

#= 2c. bundle the (already signed) event daemon and its installer: the app's "Install daemon" button runs them
if [ -n "$ESDDIR" ] && [ -f "$ESDDIR/crescendo-esd" ]; then
  mkdir -p "$OUT/Contents/Resources/esd"
  cp "$ESDDIR/crescendo-esd" "$OUT/Contents/Resources/esd/crescendo-esd"
  cp "$(dirname "$0")/esd-install.sh" "$OUT/Contents/Resources/esd/esd-install.sh"
  log "bundled event daemon installer: $OUT/Contents/Resources/esd"
fi

#= 3. ad-hoc sign, empty entitlements, no hardened-runtime exceptions needed
codesign --force --sign - --timestamp=none --entitlements "$ENT" "$OUT" || die "codesign failed: $OUT"
codesign --verify --deep --strict "$OUT" || die "verification failed: $OUT"

#= 4. prove it: no restricted entitlement and no extension
ents=$(codesign -d --entitlements :- "$OUT" 2>/dev/null || true)
if printf '%s' "$ents" | grep -q 'com.apple.developer'; then die "restricted entitlement still present in $OUT"; fi
[ ! -e "$OUT/Contents/Library/SystemExtensions" ] || die "system extension still present in $OUT"
log "lite app ready: $OUT"
log "entitlements: none (verified); launches with SIP/AMFI on. No Endpoint Security: events come from cresc/eslogger."
