#!/bin/sh
#= local-sign.sh  version 1.0.0 (2026-11-07)
#= Ad-hoc signs ("Sign to Run Locally", codesign -s -) a built Crescendo.app and its embedded
#= system extension WITH their entitlements, inside-out: nested libs, extension, then the app.
#= Why: Xcode refuses to sign a target that has restricted entitlements (endpoint-security,
#=      system-extension.install, app groups) without a provisioning profile. codesign does not,
#=      so the Makefile builds unsigned and runs this afterwards (SIGN=local, the default).
#= Usage: local-sign.sh APP.app APP.entitlements EXTENSION.entitlements
#= Notes: $(TeamIdentifierPrefix) in the entitlements is replaced by "" (no team under local signing);
#=        any other unresolved $(...) variable aborts. Running the result still needs a Mac where
#=        AMFI/SIP allow ad-hoc code with restricted entitlements (the README dev-VM setup).
#= Exit : 0 ok | 64 usage | 66 missing input | 70 signing/verification failed
set -eu

VERSION="1.0.0"
log() { printf '%s local-sign[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

[ $# -eq 3 ] || die "usage: $0 APP.app APP.entitlements EXTENSION.entitlements" 64
APP=$1; APP_ENT=$2; EXT_ENT=$3
[ -d "$APP" ]     || die "app bundle not found: $APP (build first)" 66
[ -f "$APP_ENT" ] || die "entitlements not found: $APP_ENT" 66
[ -f "$EXT_ENT" ] || die "entitlements not found: $EXT_ENT" 66
command -v codesign >/dev/null 2>&1 || die "codesign not found (macOS only)" 66

TMP=$(mktemp -d "${TMPDIR:-/tmp}/local-sign.XXXXXX") || die "cannot create a temp dir"
trap 'rm -rf "$TMP"' EXIT

#= prep IN OUT: resolve the team prefix to "" and refuse any other unresolved build variable
prep() {
  sed 's/\$(TeamIdentifierPrefix)//g' "$1" > "$2"
  if grep -q '\$(' "$2"; then die "unresolved build variable in $1" 66; fi
}
prep "$APP_ENT" "$TMP/app.entitlements"
prep "$EXT_ENT" "$TMP/ext.entitlements"

sign() { #= sign TARGET [ENTITLEMENTS]
  if [ $# -ge 2 ]; then
    codesign --force --sign - --timestamp=none --options runtime --entitlements "$2" "$1" || die "codesign failed: $1"
  else
    codesign --force --sign - --timestamp=none --options runtime "$1" || die "codesign failed: $1"
  fi
}

#= 1. nested libraries/frameworks (none today: libCrescendo is a static library)
find "$APP/Contents" \( -name '*.dylib' -o -name '*.framework' \) -prune -print 2>/dev/null | while IFS= read -r lib; do
  log "signing nested: $lib"
  sign "$lib"
done

#= 2. system extension(s)
n=0
for ext in "$APP"/Contents/Library/SystemExtensions/*.systemextension; do
  [ -d "$ext" ] || continue
  log "signing extension: $ext"
  sign "$ext" "$TMP/ext.entitlements"
  n=$((n + 1))
done
[ "$n" -ge 1 ] || die "no .systemextension found inside $APP" 66

#= 3. the app itself (last: its seal covers the signed extension)
log "signing app: $APP"
sign "$APP" "$TMP/app.entitlements"

#= 4. verify
codesign --verify --deep --strict "$APP" || die "verification failed: $APP"
touch "$APP" "$APP/Contents"      #= Finder shows the folder time: make it the signing (build) time
log "ad-hoc signed and verified: $APP"
log "note: running it needs AMFI/SIP to allow restricted entitlements on ad-hoc code (dev VM setup in the README)"
