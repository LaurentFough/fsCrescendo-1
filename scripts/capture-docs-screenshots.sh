#!/bin/sh
#= capture-docs-screenshots.sh  version 1.0.0 (2026-11-09)
#= Guided capture of the documentation screenshots (macOS). For each entry of docs/screenshots/SHOTS.txt it tells you what to put on
#= screen, waits for Enter, then runs `screencapture -o -w` (click the window you want; no drop shadow) and saves docs/screenshots/<name>.png.
#= Usage : sh scripts/capture-docs-screenshots.sh [--only NAME] [--redo]
#=           --only NAME  capture just that shot      --redo  also re-capture shots that already exist
#= Privacy: a screenshot shows whatever is on screen: user name in paths, window titles, other apps behind the window. Use a demo
#=          folder, then LOOK at every picture before committing (pictures cannot be checked automatically).
#= Exit  : 0 ok | 64 usage | 66 missing input
set -eu

VERSION="1.0.0"
ONLY=""; REDO=0
while [ $# -gt 0 ]; do
  case "$1" in
    --only) [ $# -ge 2 ] || { echo "--only needs a name" >&2; exit 64; }; ONLY=$2; shift 2 ;;
    --redo) REDO=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo "macOS only (screencapture)" >&2; exit 66; }
command -v screencapture >/dev/null 2>&1 || { echo "screencapture not found" >&2; exit 66; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIST="$ROOT/docs/screenshots/SHOTS.txt"
[ -f "$LIST" ] || { echo "missing $LIST" >&2; exit 66; }

echo "capture-docs-screenshots $VERSION"
echo "Before you start: demo data only, no personal folders open. The first shot may ask for Screen Recording permission for your terminal."
grep -v '^#' "$LIST" | grep -v '^[[:space:]]*$' | while IFS='|' read -r name what; do
  [ -z "$ONLY" ] || [ "$ONLY" = "$name" ] || continue
  out="$ROOT/docs/screenshots/$name.png"
  if [ -f "$out" ] && [ "$REDO" -eq 0 ] && [ -z "$ONLY" ]; then echo "skip $name (exists; --redo to replace)"; continue; fi
  printf '\n== %s\n   %s\n   Press Enter, then click the window to capture (Esc skips): ' "$name" "$what"
  read -r _ < /dev/tty
  if screencapture -o -w "$out"; then
    [ -f "$out" ] && echo "   saved $out" || echo "   skipped"
  fi
done
echo
echo "Next: look at every new picture, then: make check-docs && git add docs/screenshots && git commit"
