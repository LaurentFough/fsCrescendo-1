#!/bin/sh
#= probe-sandbox-net.sh  version 1.1.0 (2026-11-07)
#= Finds out how sandbox-exec treats outbound-network rules on THIS Mac:
#=   - rule order (does a later allow beat an earlier deny, or the other way round?)
#=   - which `remote` filter spellings are accepted (tcp/ip, localhost / 127.0.0.1 / *)
#=   - what the denial line looks like in the unified log
#= It talks to a throwaway HTTP server on 127.0.0.1, so DNS and the internet do not matter.
#= Usage: probe-sandbox-net.sh [--json] [--external]
#=   --json      machine-readable result (schema cresc.sandbox-net-probe/1) instead of a table
#=   --external  also try https://example.com (DNS + TLS) with a (remote tcp "*:443") allow rule
#= Env  : PORT (default 8765), PROBE_TIMEOUT seconds (default 5)
#= Needs: macOS, sandbox-exec, curl, python3. Changes nothing on the system; the server is stopped on exit.
set -u

VERSION="1.1.0"
PORT=${PORT:-8765}
T=${PROBE_TIMEOUT:-5}
JSON=0; EXTERNAL=0

for a in "$@"; do
  case $a in
    --json) JSON=1 ;;
    --external) EXTERNAL=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "usage: $0 [--json] [--external]" >&2; exit 64 ;;
  esac
done

die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-1}"; }
case $PORT in ''|*[!0-9]*) die "PORT must be a number" 64;; esac
case $T in ''|*[!0-9]*) die "PROBE_TIMEOUT must be a whole number of seconds" 64;; esac
[ "$(uname -s)" = Darwin ] || die "this probe needs macOS (sandbox-exec)" 2
for c in sandbox-exec curl python3; do command -v "$c" >/dev/null 2>&1 || die "$c not found" 2; done

URL="http://127.0.0.1:$PORT/"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sbprobe.XXXXXX") || die "cannot create a temp dir"
RESULTS="$WORK/results.tsv"; : > "$RESULTS"

#= refuse to run if something already answers on the port: we would silently test against someone else's server
if curl -s -o /dev/null --max-time 1 "$URL" 2>/dev/null; then
  die "port $PORT is already in use (try PORT=9876)" 1
fi

#= serve an EMPTY directory on loopback only
( cd "$WORK" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 ) >/dev/null 2>&1 &
SRV=$!
#= stop the server on every way out: normal exit, Ctrl-C, kill, closed terminal, and a broken pipe
#= (e.g. `... | head`): a shell killed by an untrapped signal never runs its EXIT trap, which leaked the server
cleanup() { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 141' PIPE

ready=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  kill -0 "$SRV" 2>/dev/null || die "the test server exited immediately (is python3 usable?)" 1
  if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "$URL" 2>/dev/null)" = 200 ]; then ready=1; break; fi
  sleep 0.25
done
[ "$ready" = 1 ] || die "test server did not start on $URL" 1

#= run_case NAME PROFILE URL [no-sandbox]: record rc, verdict (ALLOWED | BLOCKED | PROFILE-ERROR) and detail
run_case() {
  name=$1; profile=$2; url=$3
  if [ "$profile" = "-" ]; then
    out=$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$T" "$url" 2>&1); rc=$?
  else
    #= first make sure the profile itself is accepted, otherwise a curl failure would be misread as a block
    if ! chk=$(sandbox-exec -p "$profile" /usr/bin/true 2>&1); then
      printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$profile" "-" "PROFILE-ERROR" "$(printf '%s' "$chk" | tr '\n\t' '  ' | cut -c1-70)" >> "$RESULTS"
      return
    fi
    out=$(sandbox-exec -p "$profile" curl -sS -o /dev/null -w '%{http_code}' --max-time "$T" "$url" 2>&1); rc=$?
  fi
  code=$(printf '%s' "$out" | tail -c 3)
  if [ "$code" = 200 ]; then verdict=ALLOWED; else verdict=BLOCKED; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$profile" "$rc" "$verdict" "$(printf '%s' "$out" | tr '\n\t' '  ' | cut -c1-70)" >> "$RESULTS"
}

L="localhost:$PORT"
run_case "C0 no sandbox (baseline)"                 "-"                                                                                    "$URL"
run_case "C1 allow default"                         "(version 1)(allow default)"                                                           "$URL"
run_case "C2 deny outbound"                         "(version 1)(allow default)(deny network-outbound)"                                    "$URL"
run_case "C3 deny, THEN allow tcp localhost"        "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"$L\"))" "$URL"
run_case "C4 allow tcp localhost, THEN deny"        "(version 1)(allow default)(allow network-outbound (remote tcp \"$L\"))(deny network-outbound)" "$URL"
run_case "C5 deny, THEN allow tcp *:PORT"           "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"*:$PORT\"))" "$URL"
run_case "C6 deny, THEN allow ip localhost"         "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip \"$L\"))" "$URL"
run_case "C7 deny, THEN allow tcp 127.0.0.1"        "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"127.0.0.1:$PORT\"))" "$URL"
run_case "C8 deny network* (all directions)"        "(version 1)(allow default)(deny network*)"                                            "$URL"
#= controls and filtered-vs-filtered rule semantics
run_case "F1 control: allow WRONG port (*:1)"        "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"*:1\"))" "$URL"
run_case "G1 filtered deny only (tcp *:PORT)"        "(version 1)(allow default)(deny network-outbound (remote tcp \"*:$PORT\"))"             "$URL"
run_case "O1 filtered allow, THEN filtered deny"     "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"*:$PORT\"))(deny network-outbound (remote tcp \"*:$PORT\"))" "$URL"
run_case "O2 filtered deny, THEN filtered allow"     "(version 1)(allow default)(deny network-outbound)(deny network-outbound (remote tcp \"*:$PORT\"))(allow network-outbound (remote tcp \"*:$PORT\"))" "$URL"
run_case "S1 broad allow *:*, THEN narrow deny"      "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"*:*\"))(deny network-outbound (remote tcp \"localhost:$PORT\"))" "$URL"
run_case "S2 narrow deny, THEN broad allow *:*"      "(version 1)(allow default)(deny network-outbound)(deny network-outbound (remote tcp \"localhost:$PORT\"))(allow network-outbound (remote tcp \"*:*\"))" "$URL"
if [ "$EXTERNAL" = 1 ]; then
  run_case "C9 external: deny, THEN allow tcp *:443" "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp \"*:443\"))" "https://example.com/"
fi

#= V NAME: verdict of the case whose name starts with NAME (e.g. C3); D NAME: its detail text
V() { awk -F'\t' -v n="$1" '$1 ~ "^"n" " {print $4; exit}' "$RESULTS"; }
D() { awk -F'\t' -v n="$1" '$1 ~ "^"n" " {print $5; exit}' "$RESULTS"; }
FIND=''
add() { FIND="${FIND:+$FIND
}$1"; }

C3=$(V C3); C4=$(V C4); F1=$(V F1); G1=$(V G1); O1=$(V O1); O2=$(V O2); S1=$(V S1); S2=$(V S2); C7=$(V C7)

#= 1. is the remote filter actually a filter? (control: an allow for the WRONG port must not open the right one)
if [ "$F1" = BLOCKED ]; then add "filters are honoured: an allow for the wrong port does not open the right one (F1)"
elif [ "$F1" = ALLOWED ]; then add "WARNING: control F1 was ALLOWED, so the remote filter may be ignored; do not trust C3-C6"; fi
if [ "$G1" = BLOCKED ]; then add "a filtered deny blocks on its own (G1)"
elif [ "$G1" = ALLOWED ]; then add "WARNING: a filtered deny did NOT block (G1)"; fi

#= 2. bare deny versus filtered allow (C3: deny first, C4: allow first)
if [ "$C3" = ALLOWED ] && [ "$C4" = ALLOWED ]; then add "a filtered allow beats a bare (unfiltered) deny in either order (C3, C4): a bare deny behaves like the operation default"
elif [ "$C3" = ALLOWED ] && [ "$C4" = BLOCKED ]; then add "a later bare deny overrides an earlier filtered allow, an earlier bare deny does not (C3, C4): later rule wins"
elif [ "$C3" = BLOCKED ] && [ "$C4" = ALLOWED ]; then add "the first rule wins even against a bare deny (C3, C4)"
elif [ "$C3" = BLOCKED ] && [ "$C4" = BLOCKED ]; then add "a bare deny won in both orders (C3, C4): the filter did not help"; fi

#= 3. filtered allow versus filtered deny with the same filter (O1: allow then deny, O2: deny then allow)
if [ "$O1" = BLOCKED ] && [ "$O2" = ALLOWED ]; then add "among filtered rules the LATER one wins (O1, O2)"
elif [ "$O1" = ALLOWED ] && [ "$O2" = BLOCKED ]; then add "among filtered rules the EARLIER one wins (O1, O2)"
elif [ "$O1" = BLOCKED ] && [ "$O2" = BLOCKED ]; then add "a filtered deny wins over a filtered allow in either order (O1, O2)"
elif [ "$O1" = ALLOWED ] && [ "$O2" = ALLOWED ]; then add "a filtered allow wins over a filtered deny in either order (O1, O2)"; fi

#= 4. broad versus narrow filters (S1: broad allow then narrow deny, S2: narrow deny then broad allow)
if [ "$S1" = BLOCKED ] && [ "$S2" = BLOCKED ]; then add "a narrow deny beats a broad allow in either order: specificity decides (S1, S2)"
elif [ "$S1" = ALLOWED ] && [ "$S2" = ALLOWED ]; then add "a broad allow beats a narrow deny in either order (S1, S2)"
elif [ "$S1" = BLOCKED ] && [ "$S2" = ALLOWED ]; then add "broad versus narrow: the later rule wins (S1, S2)"
elif [ "$S1" = ALLOWED ] && [ "$S2" = BLOCKED ]; then add "broad versus narrow: the earlier rule wins (S1, S2)"
elif [ "$S1" = PROFILE-ERROR ] || [ "$S2" = PROFILE-ERROR ]; then add "S1/S2: the profile was rejected (see the table), so broad-versus-narrow is untested"; fi

#= 5. accepted host syntax
if [ "$C7" = PROFILE-ERROR ]; then add "numeric IP hosts are rejected: $(D C7)"; fi
[ -n "$FIND" ] || add "no findings could be derived: see the table"

#= denial lines for curl from the unified log (shows the real format of a network denial).
#= logd writes asynchronously, so wait a moment first, then retry once with a wider window.
sleep 3
DENIALS=$(log show --last 3m --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "deny" AND eventMessage CONTAINS "curl"' 2>/dev/null | grep -i 'deny' | tail -n 8)
if [ -z "$DENIALS" ]; then
  sleep 3
  DENIALS=$(log show --last 10m --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "deny" AND eventMessage CONTAINS "curl"' 2>/dev/null | grep -i 'deny' | tail -n 8)
fi

if [ "$JSON" = 1 ]; then
  esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }
  printf '{"schema":"cresc.sandbox-net-probe/1","tool_version":"%s","port":%s,"macos":"%s","findings":[' "$VERSION" "$PORT" "$(sw_vers -productVersion 2>/dev/null)"
  first=1
  printf '%s\n' "$FIND" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    [ "$first" = 1 ] || printf ','
    first=0
    printf '"%s"' "$(printf '%s' "$line" | esc)"
  done
  printf '],"cases":['
  first=1
  while IFS="$(printf '\t')" read -r name profile rc verdict detail; do
    [ "$first" = 1 ] || printf ','
    first=0
    printf '{"name":"%s","profile":"%s","curl_rc":"%s","verdict":"%s","detail":"%s"}' \
      "$(printf '%s' "$name" | esc)" "$(printf '%s' "$profile" | esc)" "$rc" "$verdict" "$(printf '%s' "$detail" | esc)"
  done < "$RESULTS"
  printf '],"denial_lines":['
  first=1
  printf '%s\n' "$DENIALS" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    [ "$first" = 1 ] || printf ','
    first=0
    printf '"%s"' "$(printf '%s' "$line" | esc)"
  done
  printf ']}\n'
else
  printf '%-40s %-4s %-14s %s\n' "CASE" "rc" "VERDICT" "DETAIL"
  awk -F'\t' '{ printf "%-40s %-4s %-14s %s\n", $1, $3, $4, $5 }' "$RESULTS"
  echo
  echo "findings:"
  printf '%s\n' "$FIND" | sed 's/^/  - /'
  echo
  echo "profiles tested:"
  awk -F'\t' '{ printf "  %s\n    %s\n", $1, $2 }' "$RESULTS"
  echo
  echo "recent Sandbox denial lines for curl (copy these back):"
  if [ -n "$DENIALS" ]; then printf '%s\n' "$DENIALS" | sed 's/^/  /'; else echo "  (none found: wait a few seconds and run  make logs-replay NAMES=curl LAST=3m )"; fi
fi
