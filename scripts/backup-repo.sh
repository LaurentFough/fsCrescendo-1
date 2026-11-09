#!/bin/sh
#= backup-repo.sh  version 1.0.1 (2026-11-09)
#= Makes a complete, verified, LOCAL backup of this repository before its history is replaced:
#=   <dest>/fsCrescendo-backup-<date>/all.bundle   every branch and tag in one file (git bundle), verified
#=   <dest>/fsCrescendo-backup-<date>/mirror.git   a bare mirror clone (browse with git --git-dir)
#=   <dest>/fsCrescendo-backup-<date>/worktree.tar.gz  the working folder as it is now (untracked files included, build products left out)
#=   <dest>/fsCrescendo-backup-<date>/SHA256SUMS and RESTORE.txt
#= The backup contains the OLD history. Keep it offline (an encrypted disk image is ideal) and never push it anywhere public.
#= Usage : sh scripts/backup-repo.sh [DEST_DIR]        (default DEST_DIR: ~/Backups)
#= Exit  : 0 ok | 1 verification failed | 2 not a git checkout
set -eu

VERSION="1.0.1"
log() { printf '%s backup[%s] %s\n' "$(date '+%H:%M:%S')" "$VERSION" "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit "${2:-1}"; }

git rev-parse --git-dir >/dev/null 2>&1 || die "not a git checkout" 2
ROOT=$(git rev-parse --show-toplevel)
#= a shallow clone has no complete history: its bundle cannot be restored, so refuse instead of making a useless backup
if [ "$(git -C "$ROOT" rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
  die "this is a SHALLOW clone (incomplete history). Run:  git fetch --unshallow   and try again" 1
fi
DEST_BASE=${1:-"$HOME/Backups"}
STAMP=$(date +%Y%m%d-%H%M%S)
DEST="$DEST_BASE/fsCrescendo-backup-$STAMP"
[ ! -e "$DEST" ] || die "$DEST already exists"
mkdir -p "$DEST"
chmod 700 "$DEST"

log "1/4 bundle of all refs"
git -C "$ROOT" bundle create "$DEST/all.bundle" --all >/dev/null 2>&1 || die "git bundle failed"
git -C "$ROOT" bundle verify "$DEST/all.bundle" >/dev/null 2>&1 || die "bundle does not verify"

log "2/4 bare mirror"
git clone --mirror --quiet "$ROOT" "$DEST/mirror.git" || die "mirror clone failed"
git --git-dir="$DEST/mirror.git" fsck --no-progress >/dev/null 2>&1 || die "mirror fsck failed"

log "3/4 working folder"
( cd "$ROOT" && tar --exclude='./build' --exclude='./.git' -czf "$DEST/worktree.tar.gz" . ) || die "tar failed"

log "4/4 checksums and notes"
( cd "$DEST" && { shasum -a 256 all.bundle worktree.tar.gz 2>/dev/null || sha256sum all.bundle worktree.tar.gz; } > SHA256SUMS )
commits=$(git -C "$ROOT" rev-list --all --count)
cat > "$DEST/RESTORE.txt" <<NOTES
Backup of fsCrescendo made $(date '+%Y-%m-%d %H:%M:%S') ($commits commits, all refs).

Restore a full repository:     git clone all.bundle fsCrescendo-restored
Inspect without restoring:     git --git-dir=mirror.git log --oneline --all
Restore the working folder:    mkdir restored && tar -xzf worktree.tar.gz -C restored
Check the files:               shasum -a 256 -c SHA256SUMS

This backup holds the OLD history. Keep it private; do not push it.
NOTES
log "done: $DEST ($commits commits)"
du -sh "$DEST" 2>/dev/null | sed 's/^/        size: /'
