#!/bin/sh
#= esd-install.sh  version 1.1.0 (2026-11-08)
#= Installs / removes the Crescendo event daemon as a root LaunchDaemon (run with sudo; the Makefile does).
#= Usage : esd-install.sh install --uid N --binary PATH
#=         esd-install.sh remove
#= Effect: copies the binary to /Library/PrivilegedHelperTools/com.loff.crescendo.esd (root:wheel 755) KEEPING its
#=         signature (sign it first as your user: scripts/esd-sign.sh; root cannot use your keychain), writes
#=         /Library/LaunchDaemons/com.loff.crescendo.esd.plist and loads it with launchctl bootstrap.
#=         The daemon is idle until the app asks it to start eslogger. Log: /var/log/crescendo-esd.log
#= Exit  : 0 ok | 64 usage | 66 missing input | 70 failure | 77 not root
set -eu

VERSION="1.1.0"
LABEL="com.loff.crescendo.esd"
BIN="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SOCK="/var/run/$LABEL.sock"
LOG="/var/log/crescendo-esd.log"

log() { printf '%s esd-install[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-70}"; }

[ "$(uname -s)" = Darwin ] || die "macOS only" 64
[ "$(id -u)" -eq 0 ] || die "run as root: sudo sh $0 ..." 77
[ $# -ge 1 ] || die "usage: $0 install --uid N --binary PATH | remove" 64
ACTION=$1; shift

unload() { launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true; }

case "$ACTION" in
  remove)
    unload
    rm -f "$PLIST" "$BIN" "$SOCK"
    log "removed $LABEL (log kept: $LOG)"
    log "also remove it from Full Disk Access in System Settings if you added it"
    ;;
  install)
    UID_ARG=""; SRC=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --uid) UID_ARG=${2:-}; shift 2 ;;
        --binary) SRC=${2:-}; shift 2 ;;
        *) die "unknown argument: $1" 64 ;;
      esac
    done
    case "$UID_ARG" in ''|*[!0-9]*) die "--uid must be a number" 64 ;; esac
    [ "$UID_ARG" -gt 0 ] || die "--uid must not be root" 64
    [ -f "$SRC" ] || die "binary not found: $SRC (run: make esd-build)" 66

    unload
    mkdir -p /Library/PrivilegedHelperTools
    cp "$SRC" "$BIN"
    chown root:wheel "$BIN"; chmod 755 "$BIN"
    codesign --verify --strict "$BIN" || die "the binary is not validly signed: run scripts/esd-sign.sh on it first" 66
    kind=$(codesign -dv "$BIN" 2>&1 | sed -n "s/^Signature=//p;s/^TeamIdentifier=/team /p" | tr "\n" " ")
    log "installed $BIN (signature: ${kind:-unknown})"
    case "$kind" in *adhoc*) log "ad-hoc signature: Full Disk Access will be forgotten when you rebuild (see docs/event-daemon.md)";; esac

    cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN</string>
		<string>--uid</string><string>$UID_ARG</string>
		<string>--socket</string><string>$SOCK</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>$LOG</string>
	<key>StandardOutPath</key><string>$LOG</string>
</dict>
</plist>
PLISTEOF
    chown root:wheel "$PLIST"; chmod 644 "$PLIST"
    launchctl bootstrap system "$PLIST" || die "launchctl bootstrap failed (see: launchctl print system/$LABEL)"
    log "loaded $LABEL; socket $SOCK (owner uid $UID_ARG, mode 0600)"
    log "NEXT: System Settings > Privacy & Security > Full Disk Access > + > $BIN (press Cmd-Shift-G to type the path)"
    ;;
  *) die "unknown action: $ACTION" 64 ;;
esac
