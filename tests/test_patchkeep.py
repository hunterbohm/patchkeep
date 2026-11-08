import os
import sys
import tempfile
import unittest

os.environ["PATCHKEEP_CONFIG"] = os.path.join(tempfile.mkdtemp(), "missing.toml")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import patchkeep as v  # noqa: E402


def finding(**kw):
    base = {"repo": "me/app", "path": "package-lock.json", "source": "cve.now", "eco": "npm",
            "pkg": "qs", "version": "6.16.0", "id": "CVE-2026-1", "cvss": 5.3, "kev": False, "title": ""}
    base.update(kw)
    return base


class Matching(unittest.TestCase):
    def test_canonical_prefers_cve(self):
        self.assertEqual(v.canonical(["GHSA-aaaa", "cve-2026-9"]), "CVE-2026-9")
        self.assertEqual(v.canonical([None, "GHSA-aaaa"]), "GHSA-aaaa")

    def test_dedupe_merges_sources_and_paths(self):
        out = v.dedupe([
            finding(),
            finding(source="dependabot", path="web/package-lock.json", version=None, patched="6.17.1"),
            finding(pkg="vite", id="CVE-2026-2", kev=True),
        ])
        self.assertEqual(len(out), 2)
        qs = out["me/app|qs|CVE-2026-1"]
        self.assertEqual(qs["paths"], ["package-lock.json", "web/package-lock.json"])
        self.assertEqual(qs["version"], "6.16.0")
        self.assertEqual(qs["patched"], "6.17.1")

    def test_severity_words(self):
        self.assertEqual(v.sev_word({"cvss": 9.8}), "critical")
        self.assertEqual(v.sev_word({"cvss": 7.0}), "high")
        self.assertEqual(v.sev_word({"cvss": 2.0, "kev": True}), "actively exploited")

    def test_set_hash_ignores_order(self):
        a, b = finding(), finding(pkg="vite")
        self.assertEqual(v.set_hash([a, b]), v.set_hash([b, a]))

    def test_uv_lock_becomes_requirements(self):
        text = '[[package]]\nname = "httpx"\nversion = "0.28.1"\nsource = { registry = "https://pypi.org/simple" }\n' \
               '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n'
        body, name = v.uv_lock_as_requirements(text)
        self.assertEqual((body, name), ("httpx==0.28.1\n", "requirements.txt"))


class ReviewDiff(unittest.TestCase):
    def test_foreign_hosts_only_in_added_lockfile_lines(self):
        diff = ("diff --git a/package-lock.json b/package-lock.json\n"
                '+      "resolved": "https://registry.npmjs.org/qs/-/qs-6.17.1.tgz",\n'
                '+      "resolved": "https://evil.example.com/qs.tgz",\n'
                '-      "resolved": "https://old.example.org/qs.tgz",\n'
                "diff --git a/README.md b/README.md\n"
                "+see https://docs.example.net\n")
        self.assertEqual(v.foreign_sources(diff), ["evil.example.com"])

    def test_small_diff_is_untouched(self):
        diff = "diff --git a/package.json b/package.json\n+x\n"
        self.assertEqual(v.reduce_diff(diff), diff)

    def test_big_lockfile_keeps_every_changed_package_line(self):
        filler = "\n".join(' "unchanged-context-line-%d": {}' % i for i in range(40000))
        lock = ("diff --git a/package-lock.json b/package-lock.json\n" + filler + "\n"
                '+    "node_modules/unexpected-package": {\n'
                '+      "version": "1.0.0",\n'
                '+      "integrity": "sha512-AAAA",\n')
        small = "diff --git a/requirements.txt b/requirements.txt\n+newpkg==1.0\n"
        out = v.reduce_diff(lock + small + "x" * (v.REVIEW_MAX_CHARS - len(lock)))
        self.assertIsNotNone(out)
        self.assertIn('"node_modules/unexpected-package"', out)
        self.assertIn('"version": "1.0.0"', out)
        self.assertNotIn("sha512-AAAA", out)
        self.assertNotIn("unchanged-context-line-5", out)
        self.assertIn("newpkg==1.0", out)


class Messages(unittest.TestCase):
    def test_pkg_list(self):
        self.assertEqual(v.pkg_list(["qs 6.16.0 -> 6.17.1 (CVE-1)", "qs again", "vite 8 -> 9"]), "qs, vite")
        self.assertEqual(v.pkg_list([]), "")

    def test_ignore_patterns(self):
        v.CFG["github"]["ignore"] = ["me/old-*", "me/exact", "me/app.v1"]
        try:
            self.assertTrue(v.ignored("me/old-site"))
            self.assertTrue(v.ignored("me/exact"))
            self.assertFalse(v.ignored("me/exactly"))
            self.assertTrue(v.ignored("me/app.v1"))
            self.assertFalse(v.ignored("me/app-v1"))
            self.assertTrue(v.ignored("Me/Old-Site"))
        finally:
            v.CFG["github"]["ignore"] = []


class Notify(unittest.TestCase):
    def test_failed_send_is_retried_on_an_idle_pass(self):
        out = os.path.join(tempfile.mkdtemp(), "sent.txt")
        v.LOG_DIR = tempfile.mkdtemp()
        v.CFG["notify"]["command"] = "exit 1"
        try:
            state = {}
            v.notify(["Vulnerable: app"], state)
            self.assertEqual(state["notify_pending"], ["Vulnerable: app"])
            v.CFG["notify"]["command"] = "cat > %s" % out
            v.notify([], state)
            self.assertEqual(open(out).read(), "Vulnerable: app\n")
            self.assertEqual(state["notify_pending"], [])
        finally:
            v.CFG["notify"]["command"] = ""


class Dirs(unittest.TestCase):
    def setUp(self):
        self.saved = (v.STATE_DIR, v.WORK_ROOT)

    def tearDown(self):
        v.STATE_DIR, v.WORK_ROOT = self.saved

    def test_state_dir_must_be_under_home(self):
        v.STATE_DIR, v.WORK_ROOT = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.assertIn("inside $HOME", v.dir_problem())

    def test_work_root_must_be_outside_home(self):
        home_dir = tempfile.mkdtemp(dir=v.HOME)
        try:
            v.STATE_DIR, v.WORK_ROOT = home_dir, home_dir
            self.assertIn("outside $HOME", v.dir_problem())
        finally:
            os.rmdir(home_dir)


if __name__ == "__main__":
    unittest.main()
