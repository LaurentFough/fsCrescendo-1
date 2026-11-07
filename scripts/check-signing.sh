#!/bin/sh
#= check-signing.sh  version 1.0.0 (2026-11-07)
#= Verifies the Xcode project only uses "Sign to Run Locally" (ad-hoc) signing:
#= no Apple Team ID, no certificate identity, no provisioning profile.
#= Meant for pre-commit hooks and CI; POSIX sh + awk, runs on macOS and Linux.
#= Usage: check-signing.sh [--json] [--quiet] [PBXPROJ]
#=   --json   machine-readable result (schema cresc.signing-check/1)
#=   --quiet  print only violations
#=   PBXPROJ  default: CrescendoFramework.xcodeproj/project.pbxproj (relative to the repo root)
#= Exit   : 0 ok | 1 violations | 64 usage | 66 file missing
#= FAIL   : DEVELOPMENT_TEAM / DevelopmentTeam non-empty
#=          CODE_SIGN_IDENTITY not "-" (an empty value is accepted)
#=          PROVISIONING_PROFILE / PROVISIONING_PROFILE_SPECIFIER non-empty
#= Info   : CODE_SIGN_STYLE, ProvisioningStyle, PRODUCT_BUNDLE_IDENTIFIER (listed for review)
set -eu

VERSION="1.0.0"
JSON=0; QUIET=0; FILE=''

while [ $# -gt 0 ]; do
  case $1 in
    --json)  JSON=1 ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) echo "usage: $0 [--json] [--quiet] [PBXPROJ]" >&2; exit 64 ;;
    *) FILE=$1 ;;
  esac
  shift
done

if [ -z "$FILE" ]; then
  cd "$(dirname "$0")/.."
  FILE=CrescendoFramework.xcodeproj/project.pbxproj
fi
[ -r "$FILE" ] || { echo "ERROR: cannot read $FILE" >&2; exit 66; }

#= RAW: one line per signing-related setting: LINE<TAB>KEY<TAB>VALUE<TAB>VERDICT
RAW=$(awk '
  function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
  {
    line = $0
    gsub(/\[[^]]*\]/, "", line)                       # drop conditions such as [sdk=macosx*]
    if (line !~ /^[ \t]*"?(DEVELOPMENT_TEAM|DevelopmentTeam|CODE_SIGN_IDENTITY|PROVISIONING_PROFILE_SPECIFIER|PROVISIONING_PROFILE|CODE_SIGN_STYLE|ProvisioningStyle|PRODUCT_BUNDLE_IDENTIFIER)"?[ \t]*=/) next
    key = line; sub(/^[ \t]*"?/, "", key); sub(/"?[ \t]*=.*$/, "", key)
    val = line; sub(/^[^=]*=[ \t]*/, "", val); sub(/[ \t]*;[ \t]*$/, "", val)
    val = trim(val)
    if (val ~ /^".*"$/) val = substr(val, 2, length(val) - 2)
    verdict = "info"
    if ((key == "DEVELOPMENT_TEAM" || key == "DevelopmentTeam") && val != "") verdict = "FAIL"
    if (key == "CODE_SIGN_IDENTITY" && val != "" && val != "-") verdict = "FAIL"
    if ((key == "PROVISIONING_PROFILE" || key == "PROVISIONING_PROFILE_SPECIFIER") && val != "") verdict = "FAIL"
    printf "%d\t%s\t%s\t%s\n", NR, key, val, verdict
  }' "$FILE")

FAILS=$(printf '%s\n' "$RAW" | awk -F'\t' '$4 == "FAIL"' | wc -l | tr -d ' ')

if [ "$JSON" = 1 ]; then
  printf '%s\n' "$RAW" | awk -F'\t' -v file="$FILE" -v fails="$FAILS" -v ver="$VERSION" '
    function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
    BEGIN { printf "{\"schema\":\"cresc.signing-check/1\",\"tool_version\":\"%s\",\"file\":\"%s\",\"ok\":%s,\"violations\":%d,\"items\":[", ver, esc(file), (fails == 0 ? "true" : "false"), fails }
    NF >= 4 { printf "%s{\"line\":%d,\"key\":\"%s\",\"value\":\"%s\",\"verdict\":\"%s\"}", (n++ ? "," : ""), $1, esc($2), esc($3), $4 }
    END { print "]}" }'
else
  printf '%s\n' "$RAW" | awk -F'\t' -v file="$FILE" -v quiet="$QUIET" '
    NF < 4 { next }
    $4 == "FAIL" { printf "FAIL  %s:%s  %s = %s\n", file, $1, $2, ($3 == "" ? "\"\"" : $3) }
    $4 == "info" && quiet != 1 { printf "info  %s:%s  %s = %s\n", file, $1, $2, ($3 == "" ? "\"\"" : $3) }'
  if [ "$FAILS" -eq 0 ]; then
    [ "$QUIET" = 1 ] || echo "OK: only local (ad-hoc) signing is configured in $FILE"
  else
    echo "ERROR: $FAILS signing setting(s) in $FILE are not local-only." >&2
    echo "  Fix in Xcode: each target > Signing & Capabilities > untick 'Automatically manage signing',"  >&2
    echo "  Team: None, Signing Certificate: 'Sign to Run Locally' (Debug and Release)." >&2
  fi
fi

[ "$FAILS" -eq 0 ]
