#= cli.py  version 0.1.0 (2026-11-07)
#= Command line for fsx. JSON output (--json) is the contract for a GUI; the default output is for people.
#= Exit codes: 0 ok | 1 unexpected | 2 usage (argparse) | 65 refused/invalid data | 66 missing input
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Dict, Iterable, List, Optional, Sequence

from . import SCHEMAS, __version__
from .classify import path_entries
from .denials import Group, fold, parse_lines
from .profile import Profile, ProfileError, default_store
from .session import (SessionError, compare_groups, latest_run_number, list_runs, load_run, run_once)
from .triage import Item, suggested_prefixes, summary, triage

log = logging.getLogger("fsx")


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
            raise CliError("no grantable denial has rule id %r (run `fsx triage` to list ids)" % rid)
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
        if not args.id and not args.auto:
            raise CliError("choose what to grant: --id RULE_ID (repeatable) and/or --auto low|medium", 64)
        items = items_from_args(args)
        done = apply_grants(p, select_for_grant(items, args.id or [], args.auto), args.confirm, args.note or "")
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
                timeout=args.timeout, settle=args.settle, startup_wait=args.startup_wait)


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
    if m["stderr_tail"].strip():
        print("stderr (tail): " + m["stderr_tail"].strip().replace("\n", " | ")[-200:])
    cands = [i for i in items if i.klass == "candidate"]
    if cands:
        print(table(HEADERS, item_rows(cands)))
    return items


def cmd_run(args: argparse.Namespace) -> int:
    prof = Profile.load(args.store, args.name)
    home = args.home or os.path.expanduser("~")
    entries = path_entries(os.environ.get("PATH", ""), home)
    result = run_once(prof, **run_args(args))
    report_run(result, prof, args.json, entries, home)
    return 0


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
            line = input("\n[g low|medium|<rule ids>] grant then restart   [r] restart   [q] quit > ").strip()
        except EOFError:
            line = "q"
        if line in ("q", "quit", ""):
            return 0
        if line in ("r", "restart"):
            continue
        if line.startswith("g"):
            words = line.split()[1:]
            auto = words[0] if words and words[0] in ("low", "medium") else None
            ids = [w for w in words if w not in ("low", "medium")]
            try:
                selected = select_for_grant(items, ids, auto)
                needs = [i for i in selected if i.needs_confirm or not i.rule.verified]
                confirm = False
                if needs:
                    for i in needs:
                        print("  needs confirmation: %s  (%s risk)" % (i.rule.render(), i.risk))
                    confirm = input("type YES to grant these as well > ").strip() == "YES"
                    if not confirm:
                        selected = [i for i in selected if i not in needs]
                done = apply_grants(prof, selected, True, "granted in fsx loop (run %d)" % result.number)
            except CliError as exc:
                print("not granted: %s" % exc)
                continue
            print("granted %d rule(s): profile is now v%d" % (sum(1 for d in done if d["changed"]), prof.version))
            continue
        print("unknown command: %r" % line)


#= ---- argument parsing -------------------------------------------------------------------------------------
def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--store", default=default_store(), help="data directory (default: $FSX_HOME or ~/.local/share/fsx)")
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
    p.add_argument("--timeout", type=float, help="stop the program after this many seconds")
    p.add_argument("--settle", type=float, default=3.0, help="seconds to keep reading the log after exit (default 3)")
    p.add_argument("--startup-wait", type=float, default=1.0, help="seconds to let the log reader start (default 1)")
    p.epilog = "Put the program's own arguments after a literal --, e.g.  fsx run demo --target ./tool --write-dir ~/tmp/out -- --flag value"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="fsx", description="Sandbox-denial triage and managed sandbox sessions.")
    ap.add_argument("--version", action="version", version="fsx " + __version__)
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
        #= common options live on each leaf so they work after the sub-command: fsx profile new foo --store X
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
    q.add_argument("--id", action="append", help="rule id from `fsx triage` (repeatable)")
    q.add_argument("--auto", choices=("low", "medium"), help="grant every candidate up to this risk that needs no confirmation")
    q.add_argument("--confirm", action="store_true", help="also allow high-risk, write, exec, network or unverified rules")
    q.add_argument("--note", help="why (stored with the grant)")
    p.set_defaults(func=cmd_profile)

    p = sp.add_parser("run", help="run a program once under a profile and collect its denials")
    add_common(p); add_run_options(p); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_run)

    p = sp.add_parser("loop", help="run, review denials, grant, kill and restart (interactive)")
    add_common(p); add_run_options(p); p.set_defaults(func=cmd_loop)

    p = sp.add_parser("runs", help="list the runs of a profile")
    add_common(p); p.add_argument("name"); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_runs)

    p = sp.add_parser("compare", help="which denials a profile change resolved")
    add_common(p); p.add_argument("name"); p.add_argument("a", type=int); p.add_argument("b", type=int)
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_compare)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    #= everything after the first literal -- belongs to the program being run, not to fsx
    cmd_args: List[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd_args = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    args.cmd_args = cmd_args
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(asctime)s fsx %(levelname)s %(message)s", stream=sys.stderr)
    if args.cmd == "triage":
        if args.run is not None and not args.profile:
            ap.error("--run needs --profile")
        if args.profile and args.run is None:
            ap.error("--profile needs --run")
    if args.cmd == "profile" and args.profile_cmd == "grant" and args.run is not None:
        args.profile = args.name           #= `grant NAME --run N` reads run N of that same profile
    try:
        return int(args.func(args) or 0)
    except (CliError, ProfileError, SessionError) as exc:
        print("fsx: error: %s" % exc, file=sys.stderr)
        return exc.code if isinstance(exc, CliError) else 65
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
