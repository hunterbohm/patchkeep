"""Tests for the fixer's trust split, written against an outside security review. The writer agent is
untrusted, so each test plays a hostile writer: it edits its copy of the repo (or leaves something behind)
and the trusted side must not follow, hide, push or merge it. Git, rsync and the file system are real. Only
the outside world is faked: `gh`, the writer, the reviewer."""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_STATE = tempfile.mkdtemp(prefix="vwaudit-state-")
atexit.register(shutil.rmtree, _STATE, ignore_errors=True)
os.environ["VULNWATCH_CONFIG"] = os.path.join(_STATE, "missing.toml")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vulnwatch as V  # noqa: E402

LOCK = json.dumps({"name": "app", "lockfileVersion": 3, "packages": {
    "": {"name": "app", "dependencies": {"x": "^1.2.0"}},
    "node_modules/x": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/x/-/x-1.2.3.tgz",
                       "integrity": "sha512-aaa"}}}, indent=2) + "\n"
PACKAGE = json.dumps({"name": "app", "version": "1.0.0", "scripts": {"test": "node t.js"},
                      "dependencies": {"x": "^1.2.0"}}, indent=2) + "\n"
CI = ".github/workflows/ci.yml"
WORKFLOW = "name: ci\non: [pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n"
SEED = {"package.json": PACKAGE, "package-lock.json": LOCK, "src/index.js": "console.log(1)\n",
        ".gitignore": "ignored/\n", CI: WORKFLOW}


def sh(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


_ticks = iter(range(2_000_000_000, 4_000_000_000, 7))


def put(root, files):
    """Write files (None deletes). Each gets a new mtime: a test edit lands in the same second as the
    copy it replaces, and a size-and-mtime check would call the two the same."""
    for rel, text in files.items():
        path = os.path.join(root, rel)
        if text is None:
            os.remove(path)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(text if isinstance(text, bytes) else text.encode())
        stamp = next(_ticks)
        os.utime(path, (stamp, stamp))


def commit_all(repo, msg="c"):
    sh("git", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", msg, cwd=repo)
    return sh("git", "rev-parse", "HEAD", cwd=repo).strip()


class Branch(unittest.TestCase):
    """A clone with `origin/main` seeded from SEED and a working branch on top of it."""
    seed = SEED

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="vwaudit-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.origin, self.repo = self.tmp + "/origin.git", self.tmp + "/repo"
        sh("git", "init", "-q", "--bare", "-b", "main", self.origin)
        sh("git", "clone", "-q", self.origin, self.repo)
        put(self.repo, self.seed)
        commit_all(self.repo, "seed")
        sh("git", "push", "-q", "origin", "HEAD:main", cwd=self.repo)
        sh("git", "checkout", "-q", "-b", "work", cwd=self.repo)

    def change(self, files, msg="fix"):
        put(self.repo, files)
        return commit_all(self.repo, msg)


class RawDiff(Branch):
    seed = dict(SEED, **{".gitattributes": "package-lock.json -diff\n*.min.js binary\n"})

    def test_minus_diff_and_binary_attributes_do_not_hide_lines(self):
        self.change({"package-lock.json": LOCK.replace("1.2.3", "1.2.4"), "a.min.js": "var a=1;\n"})
        plain = sh("git", "diff", "origin/main...HEAD", cwd=self.repo)
        self.assertIn("Binary files", plain)
        diff = V.raw_diff(self.repo, "origin/main...HEAD")
        self.assertNotIn("Binary files", diff)
        self.assertIn('+      "version": "1.2.4"', diff)
        self.assertIn("+var a=1;", diff)

    def test_textconv_driver_does_not_rewrite_what_is_shown(self):
        put(self.repo, {".gitattributes": "package-lock.json diff=hide\n"})
        commit_all(self.repo, "attrs")
        sh("git", "push", "-q", "origin", "HEAD:main", cwd=self.repo)
        sh("git", "config", "diff.hide.textconv", "sed s/1[.]2[.][34]/N/", cwd=self.repo)
        self.change({"package-lock.json": LOCK.replace("1.2.3", "1.2.4")})
        self.assertEqual(sh("git", "diff", "origin/main...HEAD", cwd=self.repo), "")
        diff = V.raw_diff(self.repo, "origin/main...HEAD")
        self.assertIn('+      "version": "1.2.4"', diff)

    def test_a_driver_that_runs_a_command_is_not_run(self):
        marker = self.tmp + "/ran"
        sh("git", "config", "diff.hide.command", "touch " + marker + " #", cwd=self.repo)
        put(self.repo, {".gitattributes": "package-lock.json diff=hide\n"})
        commit_all(self.repo, "attrs")
        sh("git", "push", "-q", "origin", "HEAD:main", cwd=self.repo)
        self.change({"package-lock.json": LOCK.replace("1.2.3", "1.2.4")})
        V.raw_diff(self.repo, "origin/main...HEAD")
        self.assertFalse(os.path.exists(marker))

    def test_a_rename_is_a_delete_and_an_add(self):
        sh("git", "mv", "src/index.js", "src/main.js", cwd=self.repo)
        commit_all(self.repo, "move")
        self.assertEqual(sorted(V.changed_paths(self.repo, "main")), ["src/index.js", "src/main.js"])

    def test_a_bare_carriage_return_stays_a_carriage_return(self):
        self.change({"notes.txt": "one\rtwo\n"})
        self.assertIn("+one\rtwo", V.raw_diff(self.repo, "origin/main...HEAD"))


class QuotedNames(Branch):
    def test_names_git_quotes_even_with_quote_path_off(self):
        names = ['we"ird.txt', "back\\slash.txt", "tab\there.txt", "new\nline.txt"]
        self.change({n: "x\n" for n in names})
        self.assertEqual(sorted(V.quoted_names(V.changed_paths(self.repo, "main"))), sorted(names))

    def test_plain_non_ascii_and_space_names_are_fine(self):
        self.change({"docs/ünï code.txt": "x\n", "a b/c d.txt": "x\n"})
        paths = V.changed_paths(self.repo, "main")
        self.assertEqual(sorted(paths), ["a b/c d.txt", "docs/ünï code.txt"])
        self.assertEqual(V.quoted_names(paths), [])

    def test_a_lockfile_in_a_folder_with_spaces_keeps_its_name_in_the_diff(self):
        self.change({"my app/package-lock.json": LOCK.replace("registry.npmjs.org", "evil.example")})
        self.assertEqual(V.foreign_sources(V.raw_diff(self.repo, "origin/main...HEAD")), ["evil.example"])


class LineBreaks(unittest.TestCase):
    def test_diff_lines_split_on_newlines_only(self):
        self.assertEqual(V.diff_lines("a b\u0085c\x0bd\x0ce\x1cf\r\ng\nh"), ["a b\u0085c\x0bd\x0ce\x1cf", "g", "h"])

    def test_a_line_break_in_content_cannot_start_a_section_git_never_wrote(self):
        diff = ("diff --git a/package-lock.json b/package-lock.json\n"
                '+  "resolved": "ok" diff --git a/README.md b/README.md\n'
                '+  "resolved": "https://evil.example/x.tgz"\n')
        self.assertEqual([p for p, _ in V.split_diff(diff)], ["package-lock.json"])
        self.assertEqual(V.foreign_sources(diff), ["evil.example"])

    def test_the_same_holds_for_a_big_lockfile_that_gets_reduced(self):
        filler = "\n".join(' "context-%d": {}' % i for i in range(40000))
        lock = ("diff --git a/package-lock.json b/package-lock.json\n" + filler + "\n"
                '+  "name": "evil"\u0085diff --git a/README.md b/README.md\n+  "integrity": "sha512-AAAA",\n')
        out = V.reduce_diff(lock)
        self.assertIn('"name": "evil"', out)
        self.assertNotIn("sha512-AAAA", out)


if __name__ == "__main__":
    unittest.main()
