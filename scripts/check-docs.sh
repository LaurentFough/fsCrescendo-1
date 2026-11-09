#!/bin/sh
#= check-docs.sh  version 1.0.0 (2026-11-09)
#= Checks the documentation: every relative link and image in README.md, SECURITY.md and docs/*.md (and tools/cresc/*.md) must point at an
#= existing file, and every screenshot of docs/screenshots/SHOTS.txt should exist. Broken links are errors; missing screenshots are
#= warnings unless --strict is given.
#= Usage : sh scripts/check-docs.sh [--strict]
#= Exit  : 0 ok (warnings allowed) | 1 broken links (or missing screenshots with --strict)
set -eu

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1
cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0"/..)"

python3 - "$STRICT" <<'PY'
import os, re, sys
strict = sys.argv[1] == "1"
files = [f for f in ("README.md", "SECURITY.md") if os.path.isfile(f)]
for base in ("docs", "tools/cresc"):
    if os.path.isdir(base):
        files += [os.path.join(base, n) for n in sorted(os.listdir(base)) if n.endswith(".md")]
link = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
shots_listed = set()
if os.path.isfile("docs/screenshots/SHOTS.txt"):
    for line in open("docs/screenshots/SHOTS.txt", encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "|" in line:
            shots_listed.add(line.split("|", 1)[0].strip())
broken = []
for f in files:
    text = open(f, encoding="utf-8").read()
    text = re.sub(r"```.*?```", "", text, flags=re.S)           # links inside code blocks are examples
    for m in link.finditer(text):
        target = m.group(1)
        if re.match(r"^(https?:|mailto:|#)", target) or re.match(r"^\.\./\.\./(releases|issues|actions|pulls|wiki|security)", target):
            continue                                       # web links, anchors, and GitHub interface paths such as ../../releases
        path = os.path.normpath(os.path.join(os.path.dirname(f), target.split("#", 1)[0]))
        if not os.path.exists(path):
            stem = os.path.basename(path)[:-4] if path.startswith("docs/screenshots/") and path.endswith(".png") else None
            if stem in shots_listed:
                continue                                  # a listed screenshot that is not captured yet: reported below as a warning
            broken.append("%s -> %s" % (f, target))
missing = []
shots = "docs/screenshots/SHOTS.txt"
if os.path.isfile(shots):
    for line in open(shots, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "|" in line:
            name = line.split("|", 1)[0].strip()
            if not os.path.isfile("docs/screenshots/%s.png" % name):
                missing.append(name)
print("checked %d markdown file(s)" % len(files))
for b in broken:
    print("BROKEN LINK: " + b)
if missing:
    print("%s: %d screenshot(s) not captured yet: %s" % ("MISSING" if strict else "warning", len(missing), ", ".join(missing)))
    print("  capture them with: make screenshots")
bad = bool(broken) or (strict and bool(missing))
print("docs check:", "FAILED" if bad else "ok")
sys.exit(1 if bad else 0)
PY
