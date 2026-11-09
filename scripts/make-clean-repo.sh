#!/bin/sh
#= make-clean-repo.sh  version 1.0.0 (2026-11-09)
#= Builds a NEW git repository containing the current tracked files as ONE commit, with no history, so that nothing from the old history
#= (commit messages, earlier file versions, author names) is carried over. It never pushes anything.
#= Usage : sh scripts/make-clean-repo.sh --name "Your Name" --email ID+user@users.noreply.github.com [options]
#=           --name NAME     author and committer name of the single commit (required)
#=           --email EMAIL   author and committer address (required). Use your GitHub noreply address
#=                           (GitHub > Settings > Emails > "Keep my email addresses private") so no real address becomes public
#=           --allow-real-email   accept an address that is not a noreply address (it will be public in the history)
#=           --out DIR       where to create the repository (default: ../fsCrescendo-clean; must not exist or be empty)
#=           --branch NAME   branch name (default: main)
#= Checks : the working tree must be clean; scripts/check-pii.sh must pass; afterwards the new repository is checked with --history.
#= Exit   : 0 ok | 1 a check failed | 64 usage
set -eu

VERSION="1.0.0"
NAME=""; EMAIL=""; OUT=""; BRANCH="main"; REAL=0
log() { printf '%s make-clean-repo[%s] %s\n' "$(date '+%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-1}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --name) [ $# -ge 2 ] || die "--name needs a value" 64; NAME=$2; shift 2 ;;
    --email) [ $# -ge 2 ] || die "--email needs a value" 64; EMAIL=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value" 64; OUT=$2; shift 2 ;;
    --branch) [ $# -ge 2 ] || die "--branch needs a value" 64; BRANCH=$2; shift 2 ;;
    --allow-real-email) REAL=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" 64 ;;
  esac
done
[ -n "$NAME" ] && [ -n "$EMAIL" ] || die "--name and --email are required (see --help)" 64
case "$EMAIL" in *@*.*) ;; *) die "that does not look like an email address: $EMAIL" 64 ;; esac
case "$EMAIL" in
  *@users.noreply.github.com|noreply@*) ;;
  *) [ "$REAL" -eq 1 ] || die "$EMAIL is not a noreply address and would become public. Use your GitHub noreply address, or pass --allow-real-email" 1 ;;
esac
printf '%s' "$BRANCH" | grep -Eq '^[A-Za-z0-9._/-]+$' || die "bad branch name: $BRANCH" 64

git rev-parse --git-dir >/dev/null 2>&1 || die "run this inside the repository" 1
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes: commit or stash them first" 1
[ -n "$OUT" ] || OUT="$(dirname "$ROOT")/fsCrescendo-clean"
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then die "$OUT exists and is not empty" 1; fi

log "checking the current files for personal data"
sh scripts/check-pii.sh || die "fix the findings above first" 1

log "exporting tracked files (no history) to $OUT"
mkdir -p "$OUT"
git archive --format=tar HEAD | tar -x -C "$OUT"

log "creating the single commit"
cd "$OUT"
git init -q -b "$BRANCH"
git config user.name "$NAME"
git config user.email "$EMAIL"
git add -A
git commit -q -F - <<MSG
Initial public release of fsCrescendo

File-activity inspector and sandbox workbench for macOS (the "lite" build with an event
daemon and the cresc engine), based on Crescendo by Stephen Davis (MIT licence, see LICENSE).
MSG

log "verifying the new repository"
n=$(git rev-list --count HEAD)
[ "$n" -eq 1 ] || die "expected exactly 1 commit, found $n" 1
authors=$(git log --format='%an <%ae>' | sort -u)
sh scripts/check-pii.sh --history --quiet || die "the new repository still has findings (see above)" 1
files=$(git ls-files | wc -l | tr -d ' ')

log "done."
printf '\n  repository : %s\n  commits    : 1\n  files      : %s (same as the source: %s)\n  author     : %s\n  branch     : %s\n' \
  "$OUT" "$files" "$(git -C "$ROOT" ls-files | wc -l | tr -d ' ')" "$authors" "$BRANCH"
cat <<NEXT

Next (nothing has been pushed):
  1. On GitHub create a NEW EMPTY repository (no README, no licence, no .gitignore); do not fork.
  2. cd "$OUT"
     git remote add origin <URL of the new repository>
     git push -u origin $BRANCH
  3. In the new repository: Settings > Code security > enable "Private vulnerability reporting"; Settings > Actions > General > allow actions;
     then push a tag to try the release workflow:  git tag v0.1.0 && git push origin v0.1.0
NEXT
