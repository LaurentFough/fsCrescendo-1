#!/bin/sh
#= check-pii.sh  version 1.0.0 (2026-11-09)
#= Fails when tracked files (and, with --history, commit metadata and history) contain things that identify a person or a machine:
#=   email addresses | home folders of real users | tokens and private keys | Apple team ids and signing identities |
#=   public IP addresses | MAC addresses | *.local host names | claude.ai session links
#= Allowed on purpose: the placeholders /Users/me and /Users/alice, loopback and documentation IP ranges, noreply addresses of
#= GitHub and Anthropic. Everything else must be listed in .pii-allow (one extended regex per line, matched against "file:line:text").
#= Usage : sh scripts/check-pii.sh [--history] [--quiet]
#= Exit  : 0 clean | 1 findings | 2 not a git checkout
set -eu

VERSION="1.0.0"
HISTORY=0; QUIET=0
for arg in "$@"; do
  case "$arg" in
    --history) HISTORY=1 ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 64 ;;
  esac
done
git rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git checkout" >&2; exit 2; }
cd "$(git rev-parse --show-toplevel)"

ALLOW=.pii-allow
FOUND=0
TMP=$(mktemp "${TMPDIR:-/tmp}/check-pii.XXXXXX")
trap 'rm -f "$TMP"' EXIT

#= report NAME REGEX [POSTFILTER]: print matches of REGEX in tracked text files, minus POSTFILTER and the allowlist
report() {
  name=$1; regex=$2; post=${3:-^$}
  git grep -I -n -i -E "$regex" -- . ':!*.pbxproj' ':!.pii-allow' ':!scripts/check-pii.sh' 2>/dev/null | grep -v -i -E "$post" > "$TMP" || true
  if [ -f "$ALLOW" ]; then
    grep -v -E -f "$ALLOW" "$TMP" > "$TMP.2" 2>/dev/null || true
    mv "$TMP.2" "$TMP"
  fi
  if [ -s "$TMP" ]; then
    FOUND=1
    echo "FOUND: $name"
    [ "$QUIET" -eq 1 ] || cut -c1-160 "$TMP" | head -10 | sed 's/^/    /'
  fi
}

report "email address" '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}' '@[0-9]x[^ ]*\.(png|jpg|pdf)|users\.noreply\.github\.com|noreply@(github|anthropic)\.com'
report "home folder of a real user" '/Users/[A-Za-z0-9._-]+' '/Users/(me|alice|shared|guest|library)([^A-Za-z0-9_-]|$)|/Users/\$|/Users/<'
report "home folder (linux)" '/home/[A-Za-z0-9._-]+' '/home/(user|runner)([^A-Za-z0-9_-]|$)'
report "token or private key" 'ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{12,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{24,}|BEGIN [A-Z ]*PRIVATE KEY'
report "Apple team id or signing identity" 'DEVELOPMENT_TEAM *= *[A-Z0-9]{10}|Apple Development: [^Y(]|Developer ID Application: [^Y(]' '^$'
report "public IP address" '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' '\b(127|10)\.[0-9]+\.[0-9]+\.[0-9]+|\b0\.0\.0\.0\b|\b203\.0\.113\.[0-9]+|\b192\.0\.2\.[0-9]+|\b198\.51\.100\.[0-9]+|\b255\.255\.255\.[0-9]+'
report "MAC address" '\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b'
report "local host name" '[A-Za-z0-9-]+\.local\b' '\.local/(share|state|bin)|\.local\b[^A-Za-z]*(share|state|bin)'
report "claude.ai session link" 'claude\.ai/code/session_'

if [ "$HISTORY" -eq 1 ]; then
  echo "-- history"
  bad=$(git log --all --format='%ae%n%ce' | sort -u | grep -v -E '^(noreply@anthropic\.com|noreply@github\.com|[0-9]+\+[A-Za-z0-9-]+@users\.noreply\.github\.com)$' || true)
  if [ -n "$bad" ]; then FOUND=1; echo "FOUND: author/committer addresses other than noreply:"; printf '%s\n' "$bad" | sed 's/^/    /'; fi
  n=$(git log --all --format=%B | grep -c 'claude\.ai/code/session_' || true)
  if [ "$n" -gt 0 ]; then FOUND=1; echo "FOUND: $n commit message line(s) with a claude.ai session link"; fi
  for pat in '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.(com|org|net|io|me|dev)' 'ghp_[A-Za-z0-9]{20,}' 'BEGIN [A-Z ]*PRIVATE KEY'; do
    c=$(git log --all --oneline -G"$pat" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$c" -gt 0 ]; then echo "NOTE: $c commit(s) touched a line matching $pat (review with: git log --all -G'$pat' -p)"; fi
  done
fi

if [ "$FOUND" -eq 0 ]; then echo "check-pii $VERSION: clean"; exit 0; fi
echo "check-pii $VERSION: findings above. Remove them, or list a regex in $ALLOW if they are intended."
exit 1
