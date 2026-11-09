#!/bin/sh
#= capture-file-events.sh  version 1.0.1 (2026-11-09)
#= Records REAL eslogger events for a scripted set of file actions, so the file-change parser can be validated:
#=   create (new name) | rename (to a new name, over an existing file) | modify | chmod | utimes | xattr | chflags | hard link |
#=   APFS clone | truncate | exchangedata | mkdir/rename/rmdir | unlink | unix socket bind+connect | (optional) disk image mount.
#= Everything happens in a fresh scratch folder in your home directory (removed afterwards). eslogger watches the WHOLE system,
#= so the output keeps ONLY events that mention the scratch folder (or the disk image) and replaces your home path by /Users/me.
#= Usage : sh scripts/capture-file-events.sh [--with-mount] [--out FILE] [--keep]
#=           --with-mount  also create, attach and detach a tiny disk image (mount / unmount events)
#=           --out FILE    where to write the result (default: ./file-events-sample.jsonl)
#=           --keep        keep the scratch folder and the raw capture (raw is NOT redacted; do not share it)
#= Needs : macOS 13+, python3, sudo (eslogger runs as root), Full Disk Access for the terminal app you run this in.
#= Exit  : 0 ok | 64 usage | 66 missing tool | 70 capture failed | 77 not allowed
set -eu

VERSION="1.0.1"
log() { printf '%s capture[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

WITH_MOUNT=0; OUT="./file-events-sample.jsonl"; KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --with-mount) WITH_MOUNT=1; shift ;;
    --out) [ $# -ge 2 ] || die "--out needs a file name" 64; OUT=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" 64 ;;
  esac
done

[ "$(uname -s)" = Darwin ] || die "macOS only" 64
major=$(sw_vers -productVersion | cut -d. -f1)
[ "$major" -ge 13 ] || die "eslogger needs macOS 13 or newer (this is $major)" 66
command -v eslogger >/dev/null 2>&1 || die "eslogger not found" 66
command -v python3 >/dev/null 2>&1 || die "python3 not found" 66
HERE=$(cd "$(dirname "$0")" && pwd)
ENGINE="$HERE/../tools/cresc"
[ -f "$ENGINE/cresc/__init__.py" ] || die "cresc engine not found at $ENGINE" 66

WORK=$(mktemp -d "$HOME/crescendo-capture.XXXXXX") || die "cannot create a scratch folder in $HOME"
#= bookkeeping lives in a SEPARATE folder so that eslogger's own files do not appear in the captured folder
META=$(mktemp -d "$HOME/crescendo-capture-meta.XXXXXX") || die "cannot create a scratch folder in $HOME"
RAW="$META/raw.jsonl"; ERR="$META/eslogger.err"; PIDFILE="$META/eslogger.pid"
cleanup() {
  stop_eslogger
  if [ "$KEEP" -eq 1 ]; then log "kept $WORK and $META (the raw capture in the second one is NOT redacted)"; else rm -rf "$WORK" "$META"; fi
}
STOPPED=0
stop_eslogger() {
  #= the pid file belongs to root (root wrote it), so it is only READ here; a flag remembers that eslogger was stopped
  if [ "$STOPPED" -eq 1 ] || [ ! -s "$PIDFILE" ]; then return 0; fi
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  if [ "$(ps -p "$pid" -o comm= 2>/dev/null | sed 's|.*/||')" = eslogger ]; then
    sudo kill "$pid" 2>/dev/null || true
  fi
  STOPPED=1
  return 0
}
trap cleanup EXIT INT TERM

EVENTS="create rename unlink close truncate link clone exchangedata setattrlist setmode setowner setflags setextattr deleteextattr setacl utimes uipc_bind uipc_connect"
[ "$WITH_MOUNT" -eq 1 ] && EVENTS="$EVENTS mount unmount"

log "scratch folder: $WORK (bookkeeping: $META)"
log "sudo is needed once (eslogger runs as root)"
sudo -v || die "sudo was not granted" 77

#= root writes its pid, then replaces itself with eslogger; output goes to a file we own
sudo sh -c 'echo $$ > "$1"; shift; exec eslogger "$@"' sh "$PIDFILE" $EVENTS > "$RAW" 2> "$ERR" &
i=0
while [ ! -s "$PIDFILE" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
[ -s "$PIDFILE" ] || die "eslogger did not start: $(cat "$ERR" 2>/dev/null)"

#= wait until eslogger really delivers events: touch a marker file and look for it in the capture
wait_for() { #= wait_for TEXT : poll the raw capture for up to 15 s
  n=0
  while [ $n -lt 75 ]; do
    if grep -q "$1" "$RAW" 2>/dev/null; then return 0; fi
    sleep 0.2; n=$((n + 1))
  done
  return 1
}
#= hdiutil prints deprecation warnings on newer macOS; show everything else it says
hdi() {
  if hdiutil "$@" >/dev/null 2>"$META/hdiutil.err"; then rc=0; else rc=$?; fi
  grep -v 'is deprecated' "$META/hdiutil.err" >&2 || true
  return $rc
}
cd "$WORK"
touch crescendo-ready-marker
wait_for crescendo-ready-marker || die "eslogger started but delivered no events. Full Disk Access for this terminal? See: $(head -c 300 "$ERR")"
log "eslogger is delivering events; performing the actions"

step() { log "  $1"; sleep 0.4; }
step "create a new file";                    touch new.txt
step "modify it";                            echo hello > new.txt
step "rename to a NEW name";                 mv new.txt renamed.txt
step "rename OVER an existing file";         echo replaced > tmpfile; mv tmpfile renamed.txt
step "chmod (setmode)";                      chmod 600 renamed.txt
step "set times (utimes)";                   touch -t 202001010000 renamed.txt
step "set and delete an xattr";              xattr -w com.crescendo.test 1 renamed.txt; xattr -d com.crescendo.test renamed.txt
step "chflags (setflags)";                   chflags hidden renamed.txt; chflags nohidden renamed.txt
step "hard link";                            ln renamed.txt hard.txt
step "APFS clone";                           cp -c renamed.txt clone.txt || log "  (clone not supported on this volume, continuing)"
step "truncate";                             python3 -c 'import sys; open(sys.argv[1], "r+").truncate(0)' renamed.txt
step "exchangedata (APFS may refuse)";       echo a > ex1; echo b > ex2; python3 -c 'import ctypes, sys; ctypes.CDLL(None).exchangedata(sys.argv[1].encode(), sys.argv[2].encode(), 0)' ex1 ex2 || true
step "directory: create, rename, remove";    mkdir sub; mv sub sub2; rmdir sub2
step "unix socket bind and connect" 
python3 - "$WORK/s.sock" <<'PYEOF' || log "  (socket step failed, continuing)"
import os, socket, sys
path = sys.argv[1]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(path); srv.listen(1)
cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); cli.connect(path)
cli.close(); srv.close(); os.unlink(path)
PYEOF
if [ "$WITH_MOUNT" -eq 1 ]; then
  step "disk image: create, attach, detach"
  mkdir mnt
  hdi create -size 8m -fs APFS -volname CrescCapture -ov t.dmg
  hdi attach -nobrowse -mountpoint "$WORK/mnt" t.dmg
  sleep 1
  hdi detach "$WORK/mnt"
fi
step "delete everything (unlink)";           rm -f hard.txt clone.txt renamed.txt ex1 ex2
touch crescendo-done-marker
wait_for crescendo-done-marker || log "  (the end marker never appeared; the capture may be incomplete)"
sleep 1
stop_eslogger
sleep 1

log "filtering the capture to this scratch folder and redacting your home path"
PYTHONPATH="$ENGINE" python3 -m cresc capture-filter "$RAW" "$OUT" --marker "$WORK" --marker CrescCapture --redact-home "$HOME" || die "filtering failed"
log "wrote $OUT  (send me this file; it contains only events about the scratch folder, home path replaced by /Users/me)"
