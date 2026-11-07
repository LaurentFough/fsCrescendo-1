#!/bin/sh
#= xcode-detect.sh  version 1.0.0 (2026-11-07)
#= Finds a usable full Xcode, and explains why `xcodebuild` is not usable when it is not.
#= Usage: xcode-detect.sh [--human|--env|--dir|--why]
#=   --human  readable report (default)
#=   --env    key=value lines: status, selected_dir, developer_dir, message, hint, warning, candidate (repeated)
#=   --dir    print the developer dir to use and exit 0 if a usable Xcode exists; else print nothing, exit 1
#=   --why    when no usable Xcode exists print the reason and a hint (2 lines); otherwise print nothing
#= Status : ok | clt-only | license | no-xcodebuild | unusable
#= Env    : DEVELOPER_DIR    tried first, exactly as xcode-select/xcodebuild would
#=          XD_APP_GLOBS     override the Xcode.app search globs (space separated; used by tests)
#=          XD_NO_SPOTLIGHT  1 = never call mdfind
#=          XD_DEBUG         1 = debug lines on stderr
#= Why    : /usr/bin/xcodebuild is a shim that exists even without Xcode. It fails with
#=          "requires Xcode" when xcode-select points at the Command Line Tools, or with a
#=          license error when the license was not accepted, even though Xcode is installed.
#= POSIX sh. Safe to run on any OS (reports no-xcodebuild).
set -u

VERSION="1.0.0"
MODE=${1:---human}
case $MODE in
  --human|--env|--dir|--why) ;;
  *) echo "usage: $0 [--human|--env|--dir|--why]" >&2; exit 64 ;;
esac

dbg() { if [ "${XD_DEBUG:-0}" = 1 ]; then printf 'xcode-detect[%s] %s\n' "$VERSION" "$1" >&2; fi; }
NL=$(printf '\n_'); NL=${NL%_}       #= literal newline, used as list separator

STATUS=''; DEV_DIR=''; SELECTED=''; MESSAGE=''; HINT=''; WARNING=''; CANDIDATES=''

first_line() { printf '%s\n' "$1" | sed -n '1p'; }

#= classify MESSAGE -> license | clt-only | unusable
classify() {
  case $1 in
    *[Ll]icense*)                                          echo license ;;
    *"requires Xcode"*|*"command line tools instance"*)    echo clt-only ;;
    *)                                                     echo unusable ;;
  esac
}

#= probe DIR: run `xcodebuild -version` (with DEVELOPER_DIR=DIR when DIR is non-empty); sets PRC, PMSG
probe() {
  if [ -n "$1" ]; then PMSG=$(DEVELOPER_DIR=$1 xcodebuild -version 2>&1); else PMSG=$(xcodebuild -version 2>&1); fi
  PRC=$?
  dbg "probe '${1:-<selected>}' rc=$PRC"
}

#= first_launch_ok DIR: 0 when Xcode's first-launch components are installed
first_launch_ok() {
  if [ -n "$1" ]; then DEVELOPER_DIR=$1 xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1
  else xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1; fi
}

if ! command -v xcodebuild >/dev/null 2>&1; then
  STATUS=no-xcodebuild
  MESSAGE="xcodebuild not found on PATH"
  HINT="Install Xcode (App Store or developer.apple.com), or the Command Line Tools: xcode-select --install"
else
  SELECTED=$(xcode-select -p 2>/dev/null || true)
  EFFECTIVE=${DEVELOPER_DIR:-$SELECTED}
  probe ""
  if [ "$PRC" -eq 0 ]; then
    STATUS=ok
    DEV_DIR=$EFFECTIVE
    if ! first_launch_ok ""; then WARNING="Xcode first-launch components may be missing: sudo xcodebuild -runFirstLaunch"; fi
  else
    ORIG=$(classify "$PMSG")
    ORIG_MSG=$(first_line "$PMSG")

    #= look for Xcode.app bundles that are installed but not selected
    GLOBS=${XD_APP_GLOBS:-"/Applications/Xcode.app /Applications/Xcode*.app $HOME/Applications/Xcode*.app /Volumes/*/Applications/Xcode*.app /Volumes/*/Xcode*.app"}
    for app in $GLOBS; do
      [ -d "$app/Contents/Developer" ] || continue
      case "$NL$CANDIDATES$NL" in *"$NL$app$NL"*) continue ;; esac
      CANDIDATES="${CANDIDATES:+$CANDIDATES$NL}$app"
    done
    if [ -z "$CANDIDATES" ] && [ "${XD_NO_SPOTLIGHT:-0}" != 1 ] && command -v mdfind >/dev/null 2>&1; then
      while IFS= read -r app; do
        [ -n "$app" ] && [ -d "$app/Contents/Developer" ] && CANDIDATES="${CANDIDATES:+$CANDIDATES$NL}$app"
      done <<EOT
$(mdfind "kMDItemCFBundleIdentifier == 'com.apple.dt.Xcode'" 2>/dev/null)
EOT
    fi

    #= try each candidate through DEVELOPER_DIR (no sudo, no global change)
    LIC_APP=''; BAD_APP=''
    while IFS= read -r app; do
      [ -n "$app" ] || continue
      probe "$app/Contents/Developer"
      if [ "$PRC" -eq 0 ]; then
        STATUS=ok
        DEV_DIR="$app/Contents/Developer"
        MESSAGE="Xcode found at $app, but xcode-select points at: ${SELECTED:-nothing}"
        HINT="make build DEVELOPER_DIR=\"$DEV_DIR\"   (no sudo)   or select it: sudo xcode-select -s \"$DEV_DIR\""
        if ! first_launch_ok "$DEV_DIR"; then WARNING="Xcode first-launch components may be missing: sudo xcodebuild -runFirstLaunch"; fi
        break
      fi
      if [ "$(classify "$PMSG")" = license ]; then LIC_APP=$app; else BAD_APP=$app; fi
    done <<EOT
$CANDIDATES
EOT

    if [ "$STATUS" != ok ]; then
      if [ -n "$LIC_APP" ] || [ "$ORIG" = license ]; then
        STATUS=license
        MESSAGE="${LIC_APP:+Xcode found at $LIC_APP, but }the Xcode license has not been accepted${LIC_APP:+.}"
        HINT="sudo xcodebuild -license accept"
      elif [ -n "$BAD_APP" ]; then
        STATUS=unusable
        MESSAGE="Xcode found at $BAD_APP but xcodebuild fails: $ORIG_MSG"
        HINT="Run: DEVELOPER_DIR=\"$BAD_APP/Contents/Developer\" xcodebuild -version   to see the full error"
      elif [ "$ORIG" = clt-only ]; then
        STATUS=clt-only
        MESSAGE="Only the Command Line Tools are selected and no Xcode.app was found ($ORIG_MSG)"
        HINT="Install Xcode, then: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
      else
        STATUS=unusable
        MESSAGE="xcodebuild failed: $ORIG_MSG"
        HINT="Run: xcodebuild -version   to see the full error"
      fi
    fi
  fi
fi

case $MODE in
  --dir)
    if [ "$STATUS" = ok ]; then printf '%s\n' "$DEV_DIR"; exit 0; fi
    exit 1 ;;
  --why)
    if [ "$STATUS" != ok ]; then
      printf 'Xcode not usable (%s): %s\n' "$STATUS" "$MESSAGE"
      printf '  hint: %s\n' "$HINT"
    fi
    exit 0 ;;
  --env)
    printf 'status=%s\n' "$STATUS"
    printf 'selected_dir=%s\n' "$SELECTED"
    printf 'developer_dir=%s\n' "$DEV_DIR"
    printf 'message=%s\n' "$MESSAGE"
    printf 'hint=%s\n' "$HINT"
    printf 'warning=%s\n' "$WARNING"
    if [ -n "$CANDIDATES" ]; then printf '%s\n' "$CANDIDATES" | sed 's/^/candidate=/'; fi
    exit 0 ;;
  *)
    printf '  status        : %s\n' "$STATUS"
    printf '  selected dir  : %s\n' "${SELECTED:-n/a}"
    printf '  developer dir : %s\n' "${DEV_DIR:-n/a}"
    if [ -n "$MESSAGE" ]; then printf '  message       : %s\n' "$MESSAGE"; fi
    if [ -n "$HINT" ]; then printf '  hint          : %s\n' "$HINT"; fi
    if [ -n "$WARNING" ]; then printf '  warning       : %s\n' "$WARNING"; fi
    if [ -n "$CANDIDATES" ]; then printf '%s\n' "$CANDIDATES" | sed 's/^/  candidate     : /'; fi
    exit 0 ;;
esac
