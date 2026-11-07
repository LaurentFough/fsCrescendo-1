#= test_parsing.py  version 0.1.0 (2026-11-07)
#= Parser, classifier, rule synthesis and triage, against the real log lines captured during this project.
import json
import os
import unittest

from cresc.classify import classify, is_path_search, path_entries, risk
from cresc.denials import Denial, Group, fold, parse_line, parse_lines
from cresc.rules import Rule, prefix_suggestions, q, synthesize
from cresc.triage import summary, suggested_prefixes, triage

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "sandbox-denials.log")
HOME = "/Users/me"
PATH = "/System/Cryptexes/App/usr/bin:$HOME/.cargo/bin:$HOME/.gem/bin:$HOME/bin:/opt/homebrew/opt/openssl/bin:/usr/bin"


def fixture_groups():
    with open(FIXTURE, encoding="utf-8") as fh:
        denials, skipped = parse_lines(fh.read().splitlines())
    return denials, skipped, fold(denials)


def find(groups, op, target, process=None):
    for g in groups:
        if g.op == op and g.target == target and (process is None or g.process == process):
            return g
    raise AssertionError("group not found: %s %s" % (op, target))


class ParseTests(unittest.TestCase):
    def test_compact_line(self):
        d = parse_line("2026-11-07 01:00:40.065 E  kernel[0:ebfff7] (Sandbox) Sandbox: the-binary(45318) "
                       "deny(1) sysctl-read kern.bootargs")
        self.assertEqual((d.process, d.pid, d.op, d.target, d.count), ("the-binary", 45318, "sysctl-read", "kern.bootargs", 1))
        self.assertEqual(d.ts, "2026-11-07 01:00:40.065")

    def test_duplicate_report_adds_n(self):
        d = parse_line("2026-11-07 01:00:40.067 E  kernel[0:ebfff7] (Sandbox) 3 duplicate reports for Sandbox: "
                       "the-binary(45318) deny(1) sysctl-read kern.bootargs")
        self.assertEqual(d.count, 3)

    def test_process_name_with_spaces_and_parens(self):
        d = parse_line("x (Sandbox) Sandbox: Google Chrome Helper (Renderer)(900) deny(1) file-read-data /tmp/a b")
        self.assertEqual(d.process, "Google Chrome Helper (Renderer)")
        self.assertEqual(d.pid, 900)
        self.assertEqual(d.target, "/tmp/a b")

    def test_no_target(self):
        d = parse_line("(Sandbox) Sandbox: tool(901) deny(1) process-fork")
        self.assertEqual((d.op, d.target), ("process-fork", ""))

    def test_ndjson_line(self):
        line = json.dumps({"timestamp": "2026-11-07 01:00:40.065000+0000", "eventMessage":
                           "Sandbox: curl(77) deny(1) network-outbound 203.0.113.5:443"})
        d = parse_line(line)
        self.assertEqual((d.process, d.pid, d.op, d.target), ("curl", 77, "network-outbound", "203.0.113.5:443"))
        self.assertTrue(d.ts.startswith("2026-11-07"))

    def test_bare_message(self):
        self.assertEqual(parse_line("Sandbox: a(1) deny(1) mach-lookup com.example.x").target, "com.example.x")

    def test_non_denials(self):
        for line in ("", "   ", "hello world", "{not json", "[1,2]", '{"eventMessage": "unrelated"}',
                     "Filtering the log data using \"sender == Sandbox\""):
            self.assertIsNone(parse_line(line), line)

    def test_fixture_counts(self):
        denials, skipped, groups = fixture_groups()
        self.assertEqual(skipped, 1)                       #= the deliberate non-denial line
        self.assertGreater(len(denials), 30)
        self.assertEqual(find(groups, "sysctl-read", "kern.bootargs").count, 3)      #= 2 lines + 1 duplicate report
        self.assertEqual(find(groups, "file-read-metadata", "$HOME/bin").count, 2)
        g = find(groups, "file-write-create", '/Users/me/Library/Caches/x y/file "name".tmp')
        self.assertEqual(g.process, "Google Chrome Helper (Renderer)")

    def test_fold_merges_pids_and_orders(self):
        a = Denial("p", 1, "sysctl-read", "x", 1, "t1")
        b = Denial("p", 2, "sysctl-read", "x", 2, "t2")
        [g] = fold([a, b])
        self.assertEqual((g.count, g.first_ts, g.last_ts, g.pids), (3, "t1", "t2", [1, 2]))


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.entries = path_entries(PATH, HOME)
        _, _, self.groups = fixture_groups()

    def klass(self, op, target):
        return classify(find(self.groups, op, target), self.entries, HOME)[0]

    def test_benign_list(self):
        self.assertEqual(self.klass("file-read-data", "/dev/dtracehelper"), "benign")
        self.assertEqual(self.klass("file-read-metadata", "/System/Cryptexes/Rosetta"), "benign")
        self.assertEqual(self.klass("network-outbound", "/private/var/run/syslog"), "benign")
        self.assertEqual(self.klass("mach-lookup", "com.apple.system.notification_center"), "benign")

    def test_path_search_noise(self):
        for target in ("$HOME/.gem", "$HOME/.cargo", "$HOME/bin", "/opt/homebrew/opt/openssl", "/System/Cryptexes/App"):
            self.assertEqual(self.klass("file-read-metadata", target), "path-search", target)

    def test_real_candidates(self):
        self.assertEqual(self.klass("mach-lookup", "com.apple.system.opendirectoryd.libinfo"), "candidate")
        self.assertEqual(self.klass("file-read-metadata", "/var"), "candidate")
        self.assertEqual(self.klass("file-read-metadata", "/System/Cryptexes/OS"), "candidate")
        self.assertEqual(self.klass("sysctl-read", "hw.pagesize_compat"), "candidate")

    def test_path_search_needs_a_path_entry(self):
        self.assertFalse(is_path_search("file-read-metadata", "/etc", self.entries, HOME))
        self.assertFalse(is_path_search("file-read-data", "$HOME/bin", self.entries, HOME))   #= only metadata stats
        self.assertFalse(is_path_search("file-read-metadata", "", self.entries, HOME))

    def test_risk_tiers(self):
        self.assertEqual(risk("sysctl-read", "kern.bootargs"), "low")
        self.assertEqual(risk("file-read-metadata", "/var"), "low")
        self.assertEqual(risk("mach-lookup", "x"), "medium")
        self.assertEqual(risk("file-read-data", "/private/etc/passwd"), "medium")
        self.assertEqual(risk("file-write-create", "/tmp/x"), "high")
        self.assertEqual(risk("process-fork", ""), "high")
        self.assertEqual(risk("iokit-open", "x"), "high")
        self.assertEqual(risk("file-read-data", "/Users/me/.ssh/id_ed25519", HOME), "high")   #= sensitive path
        self.assertEqual(risk("file-read-metadata", "/Users/me/.aws", HOME), "high")


class RuleTests(unittest.TestCase):
    def g(self, op, target, process="p"):
        return Group(process=process, op=op, target=target, count=1)

    def test_sysctl_and_file_and_mach(self):
        self.assertEqual(synthesize(self.g("sysctl-read", "hw.ncpu")).render(), '(allow sysctl-read (sysctl-name "hw.ncpu"))')
        self.assertEqual(synthesize(self.g("file-read-metadata", "/var")).render(),
                         '(allow file-read-metadata (literal "/var"))')
        self.assertEqual(synthesize(self.g("mach-lookup", "com.apple.system.opendirectoryd.libinfo")).render(),
                         '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))')

    def test_write_exec_fork_need_confirmation(self):
        w = synthesize(self.g("file-write-create", "/Users/me/x"))
        self.assertTrue(w.confirm)
        self.assertEqual(w.render(), '(allow file-write-create (literal "/Users/me/x"))')
        self.assertTrue(synthesize(self.g("process-exec*", "/usr/sbin/ioreg")).confirm)
        f = synthesize(self.g("process-fork", ""))
        self.assertEqual((f.render(), f.confirm), ("(allow process-fork)", True))

    def test_quotes_and_spaces_are_escaped(self):
        r = synthesize(self.g("file-write-create", '/Users/me/Library/x y/file "name".tmp'))
        self.assertEqual(r.render(), '(allow file-write-create (literal "/Users/me/Library/x y/file \\"name\\".tmp"))')
        self.assertEqual(q('a\\b'), '"a\\\\b"')

    def test_control_characters_are_refused(self):
        self.assertIsNone(synthesize(self.g("file-read-data", "/tmp/a\nb")))
        with self.assertRaises(ValueError):
            q("x\ny")

    def test_only_absolute_paths_get_rules(self):
        self.assertIsNone(synthesize(self.g("file-read-metadata", "$HOME/.gem")))
        self.assertIsNone(synthesize(self.g("file-read-data", "relative/path")))

    def test_network_rules_are_port_level_and_confirmed(self):
        r = synthesize(self.g("network-outbound", "203.0.113.5:443"))
        self.assertEqual((r.render(), r.confirm), ('(allow network-outbound (remote tcp "*:443"))', True))
        self.assertEqual(synthesize(self.g("network-outbound", "127.0.0.1:8765")).render(),
                         '(allow network-outbound (remote tcp "localhost:8765"))')
        self.assertIsNone(synthesize(self.g("network-outbound", "example.com")))
        u = synthesize(self.g("network-outbound", "/private/var/run/mDNSResponder"))
        self.assertFalse(u.verified)
        self.assertTrue(u.confirm)

    def test_unknown_operations_have_no_automatic_rule(self):
        self.assertIsNone(synthesize(self.g("iokit-open", "IOSurfaceRootUserClient")))
        self.assertIsNone(synthesize(self.g("signal", "self")))

    def test_rule_ids_are_stable_and_distinct(self):
        a = Rule("sysctl-read", "sysctl-name", "a")
        self.assertEqual(a.id, Rule("sysctl-read", "sysctl-name", "a").id)
        self.assertNotEqual(a.id, Rule("sysctl-read", "sysctl-name", "b").id)

    def test_bad_operation_name_cannot_render(self):
        with self.assertRaises(ValueError):
            Rule("file-read) (allow default", "literal", "/x").render()

    def test_prefix_suggestion_for_sibling_sysctls(self):
        rules = [Rule("sysctl-read", "sysctl-name", n) for n in
                 ("hw.optional.a", "hw.optional.b", "hw.optional.arm.c", "kern.bootargs")]
        [p] = prefix_suggestions(rules)
        self.assertEqual(p.render(), '(allow sysctl-read (sysctl-name-prefix "hw.optional."))')
        self.assertEqual(prefix_suggestions(rules[:2]), [])


class TriageTests(unittest.TestCase):
    def test_fixture_triage(self):
        _, _, groups = fixture_groups()
        items = triage(groups, path_entries(PATH, HOME), HOME)
        s = summary(items)
        self.assertEqual(s["groups"], len(groups))
        self.assertEqual(s["benign"], 5)                   #= dtracehelper, Rosetta (2 processes), syslog, notification_center
        self.assertEqual(s["path-search"], 5)
        self.assertEqual(s["candidate"], s["groups"] - 10)
        by = {(i.group.op, i.group.target): i for i in items}
        ssh = by[("file-read-data", "/Users/me/.ssh/id_ed25519")]
        self.assertEqual((ssh.risk, ssh.needs_confirm), ("high", True))
        lib = by[("mach-lookup", "com.apple.system.opendirectoryd.libinfo")]
        self.assertEqual((lib.risk, lib.needs_confirm), ("medium", False))
        self.assertIsNone(by[("file-read-data", "/dev/dtracehelper")].rule)     #= benign: no grant is suggested
        self.assertTrue(any(r.fvalue == "hw.optional." for r in suggested_prefixes(items)))

    def test_items_serialise(self):
        _, _, groups = fixture_groups()
        json.dumps([i.to_dict() for i in triage(groups, path_entries(PATH, HOME), HOME)])


if __name__ == "__main__":
    unittest.main()
