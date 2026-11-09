#= cli.py  version 0.1.0 (2026-11-07)
#= Command line for cresc. JSON output (--json) is the contract for a GUI; the default output is for people.
#= Exit codes: 0 ok | 1 unexpected | 2 usage (argparse) | 65 refused/invalid data | 66 missing input
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from typing import Dict, Iterable, List, Optional, Sequence

from . import SCHEMAS, __version__
from .classify import path_entries, risk
from .denials import Group, fold, parse_lines
from .rules import synthesize
from .export import ExportError
from .profile import Profile, ProfileError, default_store
from .scope import DEFAULT_MUTE, Filter, parse_scope
from .session import (LogWatcher, SessionError, compare_groups, latest_run_number, list_runs, load_run, run_once,
                      safe_text)
from .filechange import FILES_HEADER
from .watch import HEADER, Stats, denial_event, format_event, json_line, run_watch
from .triage import Item, suggested_prefixes, summary, triage

log = logging.getLogger("cresc")


class CliError(Exception):
    def __init__(self, message: str, code: int = 65):
        super().__init__(message)
        self.code = code


#= ---- helpers ----------------------------------------------------------------------------------------------
def read_lines(path: Optional[str]) -> List[str]:
    if path in (None, "-"):
        return sys.stdin.read().splitlines()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise CliError("cannot read %s: %s" % (path, exc), 66)


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    data = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in data)) if data else len(h) for i, h in enumerate(headers)]
    line = lambda cells: "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in data])


def emit_json(obj: Dict) -> None:
    json.dump(obj, sys.stdout, indent=2)
    sys.stdout.write("\n")


def items_from_args(args: argparse.Namespace) -> List[Item]:
    """Groups come from a log file/stdin, or from a stored run of a profile."""
    home = args.home or os.path.expanduser("~")
    entries = path_entries(args.path if args.path is not None else os.environ.get("PATH", ""), home)
    if getattr(args, "run", None) is not None:
        prof = Profile.load(args.store, args.profile)
        number = latest_run_number(prof) if args.run == "last" else int(args.run)
        groups = load_run(prof, number).groups
    else:
        denials, _ = parse_lines(read_lines(args.file))
        groups = fold(denials)
    return triage(groups, entries, home)


def item_rows(items: Sequence[Item]) -> List[List[object]]:
    return [[it.rule.id if it.rule else "-", it.klass, it.risk + ("!" if it.needs_confirm else ""), it.group.count,
             it.group.process, it.group.op, it.group.target] for it in items]


HEADERS = ["RULE", "CLASS", "RISK", "N", "PROCESS", "OPERATION", "TARGET"]


#= ---- commands ---------------------------------------------------------------------------------------------
def cmd_parse(args: argparse.Namespace) -> int:
    denials, skipped = parse_lines(read_lines(args.file))
    groups = fold(denials)
    if args.json:
        emit_json({"schema": SCHEMAS["denials"], "skipped_lines": skipped,
                   "groups": [g.to_dict() for g in groups]})
    else:
        print(table(["N", "PROCESS", "OPERATION", "TARGET"], [[g.count, g.process, g.op, g.target] for g in groups]))
        print("\n%d group(s) from %d denial line(s); %d non-denial line(s) skipped" % (len(groups), len(denials), skipped))
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    items = items_from_args(args)
    shown = items if args.all else [i for i in items if i.klass == "candidate"]
    if args.json:
        emit_json({"schema": SCHEMAS["triage"], "summary": summary(items), "items": [i.to_dict() for i in shown],
                   "prefix_suggestions": [r.to_dict() for r in suggested_prefixes(items)]})
        return 0
    print(table(HEADERS, item_rows(shown)))
    s = summary(items)
    print("\n%d group(s): %d candidate (%d low, %d medium, %d high), %d benign, %d PATH-search"
          % (s["groups"], s["candidate"], s["low"], s["medium"], s["high"], s["benign"], s["path-search"]))
    print("RISK '!' = needs --confirm to grant. Suggested rules:")
    for it in shown:
        if it.rule:
            print("  %s  %s%s" % (it.rule.id, it.rule.render(), "" if it.rule.verified else "   [syntax unverified]"))
    for r in suggested_prefixes(items):
        print("  %s  %s   [alternative: %s]" % (r.id, r.render(), r.note))
    if not args.all and s["benign"] + s["path-search"]:
        print("(%d harmless group(s) hidden; use --all to list them)" % (s["benign"] + s["path-search"]))
    return 0


def select_for_grant(items: Sequence[Item], ids: Sequence[str], auto: Optional[str]) -> List[Item]:
    grantable = [i for i in items if i.klass == "candidate" and i.rule is not None]
    by_id = {}
    for i in grantable:
        by_id.setdefault(i.rule.id, i)
    chosen: List[Item] = []
    for rid in ids:
        if rid not in by_id:
            raise CliError("no grantable denial has rule id %r (run `cresc triage` to list ids)" % rid)
        chosen.append(by_id[rid])
    if auto:
        allowed = {"low": ("low",), "medium": ("low", "medium")}[auto]
        chosen += [i for i in grantable if i.risk in allowed and not i.needs_confirm]
    seen, unique = set(), []
    for i in chosen:
        if i.rule.id not in seen:
            seen.add(i.rule.id)
            unique.append(i)
    return unique


def manual_item(text: str) -> Item:
    """A rule typed by hand as 'OPERATION TARGET', e.g. 'sysctl-read hw.pagesize'. It goes through the same rule
    synthesis, risk rating and confirmation as a logged denial, so a typo or a dangerous rule is still caught."""
    parts = text.strip().split(None, 1)
    if not parts:
        raise CliError("empty rule: expected 'OPERATION TARGET'", 64)
    op, target = parts[0], (parts[1].strip() if len(parts) > 1 else "")
    group = Group(process="(added by hand)", op=op, target=target, count=0)
    rule = synthesize(group)
    if rule is None:
        raise CliError("no rule form for %r with target %r (supported: sysctl-read, file-read-*, file-write-*, "
                       "mach-lookup, process-exec, process-fork, network-outbound)" % (op, target), 64)
    return Item(group=group, klass="candidate", reason="added by hand", risk=risk(op, target), rule=rule)


def apply_grants(prof: Profile, selected: Sequence[Item], confirm: bool, note: str) -> List[Dict]:
    risky = [i for i in selected if i.needs_confirm or not i.rule.verified]
    if risky and not confirm:
        lines = ["  %s  %s  (%s risk%s)" % (i.rule.id, i.rule.render(), i.risk,
                                            "" if i.rule.verified else ", unverified syntax") for i in risky]
        raise CliError("these grants need --confirm; nothing was granted:\n" + "\n".join(lines))
    done = []
    for i in selected:
        src = "denial: %s %s %s" % (i.group.process, i.group.op, i.group.target)
        version, changed = prof.grant(i.rule, i.risk, note, src)
        done.append({"id": i.rule.id, "rule": i.rule.render(), "version": version, "changed": changed})
    return done


def cmd_profile(args: argparse.Namespace) -> int:
    sub = args.profile_cmd
    if sub == "list":
        names = Profile.list_names(args.store)
        print("\n".join(names) if names else "(no profiles in %s)" % args.store)
        return 0
    if sub == "new":
        p = Profile.create(args.store, args.name)
        print("created profile %r (v%d) at %s" % (p.name, p.version, p.dir))
        return 0
    p = Profile.load(args.store, args.name)
    if sub == "show":
        sys.stdout.write(p.snapshot(args.version))
    elif sub == "path":
        print(p.snapshot_path(args.version))
    elif sub == "history":
        rows = [[h.get("version"), h.get("ts", ""), h.get("action"), h.get("grant", ""), h.get("risk", "")]
                for h in p.history()]
        print(table(["VERSION", "WHEN", "ACTION", "GRANT", "RISK"], rows))
    elif sub == "diff":
        sys.stdout.write(p.diff(args.a, args.b) or "(no differences)\n")
    elif sub == "revoke":
        print("revoked %s -> v%d" % (args.id, p.revoke(args.id)))
    elif sub == "grant":
        if not args.id and not args.auto and not args.manual:
            raise CliError("choose what to grant: --id RULE_ID, --auto low|medium and/or --manual 'OPERATION TARGET'", 64)
        selected: List[Item] = []
        if args.id or args.auto:                      #= only read a log/stdin when a denial source is needed
            selected = select_for_grant(items_from_args(args), args.id or [], args.auto)
        selected += [manual_item(m) for m in (args.manual or [])]
        done = apply_grants(p, selected, args.confirm, args.note or "")
        if args.json:
            emit_json({"schema": SCHEMAS["profile"], "profile": p.name, "version": p.version, "grants": done})
        else:
            for d in done:
                print("%s %s -> v%d" % ("granted" if d["changed"] else "already granted", d["rule"], d["version"]))
            if not done:
                print("nothing to grant")
    return 0


def run_args(args: argparse.Namespace) -> Dict:
    return dict(target=args.target, write_dirs=args.write_dir, args=args.cmd_args, watch=args.watch,
                timeout=args.timeout, settle=args.settle, startup_wait=args.startup_wait,
                pass_env=args.pass_env, inherit_env=args.inherit_env)


def report_run(result, profile: Profile, json_out: bool, entries: Sequence[str], home: str) -> List[Item]:
    items = triage(result.groups, entries, home)
    if json_out:
        emit_json(dict(result.meta, triage={"summary": summary(items), "items": [i.to_dict() for i in items
                                                                                  if i.klass == "candidate"]}))
        return items
    m = result.meta
    how = "timed out" if m["timed_out"] else ("interrupted" if m["interrupted"] else "exit %s" % m["exit"])
    print("run %d under %s v%d: %s after %.1fs, %d denial(s) in %d group(s)"
          % (m["run"], m["profile"], m["profile_version"], how, m["duration_s"], m["denials_total"], m["groups"]))
    sizes = [os.path.getsize(os.path.join(result.directory, n)) if os.path.isfile(os.path.join(result.directory, n)) else 0
             for n in ("stdout.txt", "stderr.txt")]
    print("output: stdout %d B, stderr %d B   (cresc output %s --run %d)" % (sizes[0], sizes[1], m["profile"], m["run"]))
    if m["stderr_tail"].strip():
        print("stderr (tail): " + safe_text(m["stderr_tail"].strip()).replace("\n", " | ")[-200:])
    cands = [i for i in items if i.klass == "candidate"]
    if cands:
        print(table(HEADERS, item_rows(cands)))
    elif m["exit"] not in (0, None) and not m["timed_out"] and not m["interrupted"]:
        print("The program failed (exit %s) but no grantable denial was logged. A denial may not be reported, or the "
              "failure has another cause. Compare with an unsandboxed run, or add a rule by hand "
              "(loop: 'a OPERATION TARGET'; profile grant --manual 'OPERATION TARGET')." % m["exit"])
    return items


def cmd_run(args: argparse.Namespace) -> int:
    prof = Profile.load(args.store, args.name)
    home = args.home or os.path.expanduser("~")
    entries = path_entries(os.environ.get("PATH", ""), home)
    result = run_once(prof, **run_args(args))
    report_run(result, prof, args.json, entries, home)
    return 0


def read_head(path: str, limit: int) -> Dict:
    """The first `limit` bytes of a run's output file, escaped for printing."""
    if not os.path.isfile(path):
        return {"bytes": 0, "truncated": False, "text": ""}
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read(limit)
    return {"bytes": size, "truncated": size > limit, "text": safe_text(data.decode("utf-8", "replace"))}


def cmd_output(args: argparse.Namespace) -> int:
    prof = Profile.load(args.store, args.name)
    number = latest_run_number(prof) if args.run == "last" else int(args.run)
    res = load_run(prof, number)
    limit = max(1, min(args.bytes, 1000000))
    #= read from the run directory itself, never from paths stored inside result.json
    streams = {n: read_head(os.path.join(res.directory, n + ".txt"), limit) for n in ("stdout", "stderr")}
    m = res.meta
    if args.json:
        emit_json({"schema": SCHEMAS["run"], "run": number, "exit": m["exit"], "args": m["args"], "cwd": m.get("cwd"),
                   "profile_version": m["profile_version"], "stdout": streams["stdout"], "stderr": streams["stderr"]})
        return 0
    print("run %d under %s v%d: exit %s, started %s" % (number, m["profile"], m["profile_version"], m["exit"], m["started"]))
    print("program  : %s" % m["target"])
    print("arguments: %s" % (" ".join(repr(a) for a in m["args"]) or "(none)"))
    print("start dir: %s" % m.get("cwd", "?"))
    for n in ("stdout", "stderr"):
        s = streams[n]
        print("\n--- %s (%d bytes%s) ---" % (n, s["bytes"], ", first %d shown" % limit if s["truncated"] else ""))
        print(s["text"].rstrip("\n") if s["text"] else "(empty)")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Zip everything about one run (record, output, denials, analysis, profile, hashes) as an evidence bundle."""
    from .export import build_bundle, default_bundle_path
    prof = Profile.load(args.store, args.name)
    number = latest_run_number(prof) if args.run == "last" else int(args.run)
    home = os.path.expanduser("~")
    out = os.path.abspath(args.output) if args.output else default_bundle_path(args.store, prof.name, number)
    result = build_bundle(prof, number, out, path_entries(os.environ.get("PATH", ""), home), home,
                          redact=not args.no_redact, force=args.force,
                          events_file=os.path.abspath(args.events) if args.events else None)
    if args.json:
        emit_json(dict(result, schema=SCHEMAS["bundle"]))
    else:
        print("bundle : %s" % result["path"])
        print("sha256 : %s   (record this elsewhere if the bundle is evidence)" % result["sha256"])
        print("files  : %d, %d bytes" % (len(result["files"]), result["bytes"]))
        if args.no_redact:
            print("NOTE   : not redacted - paths are as on this machine")
    return 0


def cmd_capture_filter(args: argparse.Namespace) -> int:
    """Reduce a raw eslogger capture to the events about the given markers, with the home folder path replaced."""
    from .capture import filter_capture
    with open(args.raw, encoding="utf-8", errors="replace") as fh:
        kept, counts = filter_capture(fh, args.marker, home=args.redact_home or os.path.expanduser("~"))
    with open(args.output, "w", encoding="utf-8") as out:
        out.write("".join(line + "\n" for line in kept))
    emit_json({"kept": len(kept), "by_event": counts, "output": os.path.abspath(args.output)})
    return 0


def cmd_recording(args: argparse.Namespace) -> int:
    """Inspect, verify, export or replay a .crescrec recording."""
    from . import recording as rec
    path = os.path.abspath(args.file)
    try:
        if args.rec_cmd == "info":
            info = rec.summarise(path)
            if args.json:
                emit_json(dict(info, schema=SCHEMAS["recording"]))
            else:
                h = info["header"] or {}
                print("%s: kind %s, created %s, %d record(s), %.1f s, %s" % (os.path.basename(path), h.get("kind"), h.get("created"),
                      info["records"], info["duration_s"], "intact" if info["ok"] else "PROBLEMS"))
                print("by type    : %s" % json.dumps(info["by_type"], sort_keys=True))
                print("by category: %s" % json.dumps(info["by_category"], sort_keys=True))
                for problem in info["problems"]:
                    print("  - %s" % problem)
            return 0 if info["ok"] else 1
        if args.rec_cmd == "verify":
            info = rec.verify_recording(path)
            print("%s: %d record(s), %s" % ("OK" if info["ok"] else "FAILED", info["records"], "complete" if info["complete"] else "NO FOOTER (incomplete)"))
            for problem in info["problems"]:
                print("  - %s" % problem)
            return 0 if info["ok"] else 1
        if args.rec_cmd == "export":
            out = os.path.abspath(args.output)
            result = rec.export_recording(path, out, args.format, force=args.force)
            print("%s: %d row(s) as %s" % (result["path"], result["rows"], result["format"]))
            return 0
        #= play: print the change rows at their recorded cadence
        done = threading.Event()

        def push(batch, position, reset, ended):
            for r in batch:
                data = r.get("data") or {}
                print(rec.change_line(data) if r.get("type") == "change" else json.dumps(r, sort_keys=True), flush=True)
            if ended:
                done.set()
        player = rec.Player(path, push, speed=args.speed, start_t=args.start, max_gap=args.max_gap)
        player.start()
        done.wait()
        return 0
    except rec.RecordingError as exc:
        raise CliError(str(exc), 66)


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    from .export import verify_bundle
    result = verify_bundle(os.path.abspath(args.bundle))
    if args.json:
        emit_json({"schema": SCHEMAS["bundle"], "ok": result["ok"], "checked": result["checked"], "problems": result["problems"]})
    else:
        print("%s: %d file(s) checked" % ("OK" if result["ok"] else "FAILED", result["checked"]))
        for problem in result["problems"]:
            print("  - %s" % problem)
    return 0 if result["ok"] else 1


def cmd_watch(args: argparse.Namespace) -> int:
    """Event view from eslogger JSON (file or pipe), scoped and optionally merged with Sandbox denials.
    Only Apple's eslogger needs root:  sudo eslogger exec fork exit open close write create rename unlink | cresc watch -"""
    scopes = []
    try:
        for kind, values in (("app", args.app), ("dir", args.dir), ("file", args.scope_file), ("pid", args.pid)):
            scopes += [parse_scope(kind, v) for v in values]
    except ValueError as exc:
        raise CliError(str(exc), 64)
    mute = [] if args.no_mute else list(DEFAULT_MUTE) + list(args.mute)
    flt = Filter(scopes, follow=not args.no_follow, mute=mute, kinds=[k.strip() for k in (args.kinds or "").split(",") if k.strip()])
    lock = threading.Lock()
    cleaner = None
    ticking = threading.Event()
    if args.files:
        from .cleanup import Cleaner
        from .filechange import FILE_EVENTS, format_change
        cleaner = Cleaner(args.cleanup, args.cleanup_window)

    def show_changes(rows) -> None:
        for change in rows:
            print(json.dumps(change.to_dict(), sort_keys=True) if args.json else format_change(change), flush=True)

    def emit(ev) -> None:
        if args.files:                      #= file-change view: events become created / deleted / modified / ... rows
            from .filechange import from_event
            for change in from_event(ev):
                with lock:
                    show_changes(cleaner.feed(change, time.monotonic()) if args.cleanup != "none" else [change])
            return
        with lock:
            print(json_line(ev) if args.json else format_event(ev), flush=True)

    def settle_loop() -> None:              #= releases cleaned rows while a live stream is quiet
        while not ticking.wait(0.5):
            with lock:
                show_changes(cleaner.settle(time.monotonic()))

    watcher = None
    if args.denials:
        def on_denial(d) -> None:
            emit(denial_event(d.process, d.pid, d.op, d.target, d.ts))
        watcher = LogWatcher(args.denials, on_denial=on_denial)
        watcher.start()
        watcher.started.wait(5)
        if watcher.error:
            raise CliError("cannot start the denial watcher: %s" % watcher.error, 65)
    stats = Stats()
    stream = None
    try:
        if args.source in (None, "-"):
            lines = sys.stdin
        else:
            try:
                stream = open(args.source, encoding="utf-8", errors="replace")
            except OSError as exc:
                raise CliError("cannot read %s: %s" % (args.source, exc), 66)
            lines = stream
        if not args.json:
            print(FILES_HEADER if args.files else HEADER, flush=True)
        if cleaner is not None and args.cleanup != "none":
            threading.Thread(target=settle_loop, daemon=True).start()
        run_watch(lines, flt, emit, stats, args.limit)
        ticking.set()
        if cleaner is not None:
            with lock:
                show_changes(cleaner.flush())
        if watcher:
            time.sleep(args.settle)                #= denials are logged asynchronously; give the last ones a moment
    finally:
        if stream:
            stream.close()
        if watcher:
            watcher.stop()
        top = ", ".join("%s %d" % kv for kv in list(stats.to_dict()["by_kind"].items())[:5])
        print("watch: %d event(s) read, %d shown, %d non-event line(s) skipped, %d dropped (gaps in the event sequence)%s"
              % (stats.read, stats.shown, stats.skipped, stats.dropped, ("; most frequent: " + top) if top else ""),
              file=sys.stderr)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Line-delimited JSON over stdin/stdout for a GUI (see PROTOCOL.md). Logs go to stderr only."""
    from .serve import Server
    for stream in (sys.stdin, sys.stdout):               #= a stray invalid byte must not crash the server
        stream.reconfigure(encoding="utf-8", errors="replace")
    return Server(args.store).serve_forever()


def cmd_runs(args: argparse.Namespace) -> int:
    prof = Profile.load(args.store, args.name)
    runs = list_runs(prof)
    if args.json:
        emit_json({"schema": SCHEMAS["run"], "runs": runs})
    else:
        print(table(["RUN", "PROFILE", "EXIT", "DENIAL GROUPS", "DENIALS", "SECONDS", "STARTED"],
                    [[r["run"], "v%d" % r["profile_version"], r["exit"], r["groups"], r["denials_total"],
                      r["duration_s"], r["started"]] for r in runs]))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    prof = Profile.load(args.store, args.name)
    a, b = load_run(prof, args.a), load_run(prof, args.b)
    diff = compare_groups(a.groups, b.groups)
    if args.json:
        emit_json(dict(diff, a=a.meta, b=b.meta))
        return 0
    print("run %d (v%d, exit %s)  ->  run %d (v%d, exit %s)" % (a.number, a.meta["profile_version"], a.meta["exit"],
                                                              b.number, b.meta["profile_version"], b.meta["exit"]))
    for label in ("resolved", "new", "persisting"):
        print("\n%s: %d" % (label.upper(), len(diff[label])))
        for r in diff[label]:
            print("  %s  %s  %s" % (r["process"], r["op"], r["target"]))
    print("\nNo denials does not prove the output is right: check the program's results as well.")
    return 0


def cmd_loop(args: argparse.Namespace) -> int:
    """Run, show the denials, let the user grant, then kill-and-restart under the new profile version."""
    prof = Profile.load(args.store, args.name)
    home = args.home or os.path.expanduser("~")
    entries = path_entries(os.environ.get("PATH", ""), home)
    while True:
        result = run_once(prof, **run_args(args))
        items = report_run(result, prof, False, entries, home)
        grantable = [i for i in items if i.klass == "candidate" and i.rule is not None]
        for i in grantable:
            print("  %s  %s" % (i.rule.id, i.rule.render()))
        try:
            line = input("\n[g low|medium|<rule ids>] grant then restart   [a OPERATION TARGET] add a rule by hand"
                         "   [r] restart   [q] quit > ").strip()
        except EOFError:
            line = "q"
        if line in ("q", "quit", ""):
            return 0
        if line in ("r", "restart"):
            continue
        if line.startswith("g") or line.startswith("a "):
            try:
                if line.startswith("a "):
                    selected = [manual_item(line[2:])]
                else:
                    words = line.split()[1:]
                    auto = words[0] if words and words[0] in ("low", "medium") else None
                    ids = [w for w in words if w not in ("low", "medium")]
                    selected = select_for_grant(items, ids, auto)
                needs = [i for i in selected if i.needs_confirm or not i.rule.verified]
                confirm = False
                if needs:
                    for i in needs:
                        print("  needs confirmation: %s  (%s risk)" % (i.rule.render(), i.risk))
                    confirm = input("type YES to grant these as well > ").strip() == "YES"
                    if not confirm:
                        selected = [i for i in selected if i not in needs]
                done = apply_grants(prof, selected, True, "granted in cresc loop (run %d)" % result.number)
            except CliError as exc:
                print("not granted: %s" % exc)
                continue
            print("granted %d rule(s): profile is now v%d" % (sum(1 for d in done if d["changed"]), prof.version))
            continue
        print("unknown command: %r" % line)


#= ---- argument parsing -------------------------------------------------------------------------------------
def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--store", default=None, help="data directory (default: $CRESC_HOME or ~/.local/share/crescendo/cresc)")
    p.add_argument("--home", help="home directory used to expand ~ and $HOME (default: yours)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")


def add_source(p: argparse.ArgumentParser, with_profile: bool = True) -> None:
    p.add_argument("file", nargs="?", help="log file, or - for stdin (default)")
    if with_profile:
        p.add_argument("--profile", help="read a stored run of this profile instead of a file")
    p.add_argument("--run", help="run number or 'last' (reads a stored run" +
                   (" of --profile)" if with_profile else " of this profile instead of a file)"))
    p.add_argument("--path", help="PATH used to recognise PATH-search noise (default: $PATH)")


def add_run_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="profile name")
    p.add_argument("--target", required=True, help="program to run (name on PATH or absolute path)")
    p.add_argument("--write-dir", action="append", required=True, help="writable directory (repeatable, max 8)")
    p.add_argument("--watch", action="append", default=[], help="extra process name whose denials to collect (repeatable)")
    p.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                   help="also give the program this environment variable (repeatable); by default it gets only "
                        "PATH HOME USER LOGNAME LANG LC_ALL LC_CTYPE TERM TMPDIR TZ")
    p.add_argument("--inherit-env", action="store_true", help="give the program your WHOLE environment (not recommended)")
    p.add_argument("--timeout", type=float, help="stop the program after this many seconds")
    p.add_argument("--settle", type=float, default=3.0, help="seconds to keep reading the log after exit (default 3)")
    p.add_argument("--startup-wait", type=float, default=1.0, help="seconds to let the log reader start (default 1)")
    p.epilog = "Put the program's own arguments after a literal --, e.g.  cresc run demo --target ./tool --write-dir ~/tmp/out -- --flag value"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cresc", description="Sandbox-denial triage and managed sandbox sessions.")
    ap.add_argument("--version", action="version", version="cresc " + __version__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("parse", help="parse Sandbox denial log lines into grouped JSON/table")
    add_common(p); p.add_argument("file", nargs="?"); p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_parse)

    p = sp.add_parser("triage", help="classify denials and suggest allow rules")
    add_common(p); add_source(p); p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="include harmless (benign / PATH-search) groups")
    p.set_defaults(func=cmd_triage)

    p = sp.add_parser("profile", help="manage versioned sandbox profiles")
    ps = p.add_subparsers(dest="profile_cmd", required=True)

    def leaf(name: str) -> argparse.ArgumentParser:
        #= common options live on each leaf so they work after the sub-command: cresc profile new foo --store X
        q = ps.add_parser(name)
        add_common(q)
        return q

    leaf("list")
    q = leaf("new"); q.add_argument("name")
    for nm in ("show", "path"):
        q = leaf(nm); q.add_argument("name"); q.add_argument("--version", type=int)
    q = leaf("history"); q.add_argument("name")
    q = leaf("diff"); q.add_argument("name"); q.add_argument("a", type=int); q.add_argument("b", type=int)
    q = leaf("revoke"); q.add_argument("name"); q.add_argument("id")
    q = leaf("grant"); q.add_argument("name"); add_source(q, with_profile=False); q.add_argument("--json", action="store_true")
    q.add_argument("--id", action="append", help="rule id from `cresc triage` (repeatable)")
    q.add_argument("--auto", choices=("low", "medium"), help="grant every candidate up to this risk that needs no confirmation")
    q.add_argument("--manual", action="append", metavar="'OPERATION TARGET'",
                   help="grant a rule by hand, e.g. 'sysctl-read hw.pagesize' (repeatable); same checks as a logged denial")
    q.add_argument("--confirm", action="store_true", help="also allow high-risk, write, exec, network or unverified rules")
    q.add_argument("--note", help="why (stored with the grant)")
    p.set_defaults(func=cmd_profile)

    p = sp.add_parser("run", help="run a program once under a profile and collect its denials")
    add_common(p); add_run_options(p); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_run)

    p = sp.add_parser("loop", help="run, review denials, grant, kill and restart (interactive)")
    add_common(p); add_run_options(p); p.set_defaults(func=cmd_loop)

    p = sp.add_parser("output", help="show a run's arguments, exit status, stdout and stderr (control characters escaped)")
    add_common(p); p.add_argument("name"); p.add_argument("--run", default="last", help="run number or 'last' (default)")
    p.add_argument("--bytes", type=int, default=4000, help="how much of each stream to show (default 4000)")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_output)

    p = sp.add_parser("watch", help="event view from eslogger JSON, scoped to apps / folders / files / pids")
    add_common(p)
    p.add_argument("source", nargs="?", help="eslogger JSON lines: a file, or - for stdin (default)")
    p.add_argument("--app", action="append", default=[], metavar="NAME|PATH|SIGNING_ID",
                   help="show this program and its children (repeatable); a path matches everything under it")
    p.add_argument("--dir", action="append", default=[], metavar="PATH", help="show events touching anything under this directory")
    p.add_argument("--file", action="append", default=[], dest="scope_file", metavar="PATH", help="show events touching this exact file")
    p.add_argument("--pid", action="append", default=[], metavar="N", help="show this process and its children (until it exits)")
    p.add_argument("--no-follow", action="store_true", help="do not follow child processes of --app / --pid")
    p.add_argument("--mute", action="append", default=[], metavar="NAME", help="also hide this process name (repeatable)")
    p.add_argument("--no-mute", action="store_true", help="show the noisy system processes that are hidden by default")
    p.add_argument("--kinds", metavar="PATTERNS", help="only these kinds, e.g. 'file.*,proc.exec' (shell-style patterns)")
    p.add_argument("--denials", action="append", default=[], metavar="NAME",
                   help="also show Sandbox denials of this process name (repeatable)")
    p.add_argument("--settle", type=float, default=2.0, help="seconds to keep listening for denials after the input ends (default 2)")
    p.add_argument("--limit", type=int, help="stop after this many shown events")
    p.add_argument("--json", action="store_true", help="one cresc.event/1 JSON object per line (cresc.filechange/1 with --files)")
    p.add_argument("--files", action="store_true",
                   help="file-change view (created, deleted, modified, attributes, moved): feed it eslogger create rename unlink close ...")
    p.add_argument("--cleanup", choices=("none", "coalesce", "prune"), default="none",
                   help="with --files: coalesce repeated changes, or prune temp files and atomic saves too (default none)")
    p.add_argument("--cleanup-window", type=float, default=2.0, metavar="S",
                   help="with --cleanup: seconds a file must be quiet before its rows are shown (default 2)")
    p.set_defaults(func=cmd_watch)

    p = sp.add_parser("serve", help="machine-readable JSON-lines interface on stdin/stdout, for a GUI (see PROTOCOL.md)")
    add_common(p); p.set_defaults(func=cmd_serve)

    p = sp.add_parser("export", help="zip one run (record, output, denials, analysis, profile, SHA-256 manifest) as an evidence bundle")
    add_common(p); p.add_argument("name"); p.add_argument("--run", default="last", help="run number or 'last' (default)")
    p.add_argument("-o", "--output", metavar="FILE.zip", help="where to write it (default: <store>/exports/)")
    p.add_argument("--events", metavar="FILE", help="also include this eslogger JSON-lines capture")
    p.add_argument("--no-redact", action="store_true", help="keep your home folder path instead of replacing it with ~")
    p.add_argument("--force", action="store_true", help="replace an existing output file")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_export)

    p = sp.add_parser("recording", help="inspect, verify, export or replay a .crescrec recording")
    add_common(p); rs = p.add_subparsers(dest="rec_cmd", required=True)
    for name in ("info", "verify", "export", "play"):
        q = rs.add_parser(name); q.add_argument("file")
        if name in ("info",):
            q.add_argument("--json", action="store_true")
        if name == "export":
            q.add_argument("-o", "--output", required=True); q.add_argument("--format", choices=("text", "csv", "json", "jsonl"), default="text")
            q.add_argument("--force", action="store_true")
        if name == "play":
            q.add_argument("--speed", type=float, default=1.0); q.add_argument("--start", type=float, default=0.0)
            q.add_argument("--max-gap", type=float, default=2.0, dest="max_gap", help="longest pause kept, in seconds (default 2)")
    p.set_defaults(func=cmd_recording)

    p = sp.add_parser("verify-bundle", help="check an evidence bundle against its manifest")
    add_common(p); p.add_argument("bundle"); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_verify_bundle)

    p = sp.add_parser("capture-filter", help="keep only the eslogger events that mention a marker (a path), redacting your home folder")
    add_common(p); p.add_argument("raw"); p.add_argument("output"); p.add_argument("--marker", action="append", required=True, metavar="TEXT")
    p.add_argument("--redact-home", metavar="PATH", help="home folder path to replace by /Users/me (default: yours)"); p.set_defaults(func=cmd_capture_filter)

    p = sp.add_parser("runs", help="list the runs of a profile")
    add_common(p); p.add_argument("name"); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_runs)

    p = sp.add_parser("compare", help="which denials a profile change resolved")
    add_common(p); p.add_argument("name"); p.add_argument("a", type=int); p.add_argument("b", type=int)
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_compare)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    #= everything after the first literal -- belongs to the program being run, not to cresc
    cmd_args: List[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd_args = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    args.cmd_args = cmd_args
    if hasattr(args, "store") and args.store is None:
        args.store = default_store()       #= resolved here, not at parser build time: --help must not move data
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(asctime)s cresc %(levelname)s %(message)s", stream=sys.stderr)
    if args.cmd == "triage":
        if args.run is not None and not args.profile:
            ap.error("--run needs --profile")
        if args.profile and args.run is None:
            ap.error("--profile needs --run")
    if args.cmd == "profile" and args.profile_cmd == "grant" and args.run is not None:
        args.profile = args.name           #= `grant NAME --run N` reads run N of that same profile
    try:
        return int(args.func(args) or 0)
    except (CliError, ProfileError, SessionError, ExportError) as exc:
        print("cresc: error: %s" % exc, file=sys.stderr)
        return exc.code if isinstance(exc, CliError) else 65
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
