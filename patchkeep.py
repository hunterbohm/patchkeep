#!/usr/bin/env python3
"""patchkeep: find vulnerable dependencies in your GitHub repos, fix them with a sandboxed
agent, get a second model to review the fix, and merge it. No human in the loop.

  patchkeep.py                       one watch pass (inventory, match, launch fixers, report)
  patchkeep.py --dry-run             one pass that prints what it would do; changes nothing
  patchkeep.py fix OWNER/REPO ITEMS  fixer for one repo (started by the watch pass)

Run the watch pass every few minutes (cron, launchd, systemd). Its stdout is the
notification text; empty stdout means nothing new. See README.md.

Trust split: the fixer agent edits a plain copy of the repo inside an OS sandbox that denies
every read and write under $HOME, so it never sees GitHub or git credentials, and treats that copy
as hostile. This script commits locally, runs every check and the reviewer on that commit, and only
then pushes, opens the PR, and merges the exact commit it pushed.

Kill switches in the state dir (default ~/.local/state/patchkeep):
  DISABLE_AUTOFIX    detect and notify only (also stops running fixers before push/merge)
  DISABLE_AUTOMERGE  fix and open PRs, never merge
"""
import base64
import fnmatch
import datetime
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import platform
import posixpath
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("PATCHKEEP_CONFIG", HOME + "/.config/patchkeep/config.toml")

DEFAULTS = {
    "state_dir": "~/.local/state/patchkeep",
    "work_root": "/tmp",
    "path": "/opt/homebrew/bin:/usr/local/bin:~/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "github": {"owners": [], "active_days": 120, "ignore": [], "include_forks": False},
    "fix": {
        "enabled": True, "automerge": True, "max_parallel": 2,
        "author_model": "gpt-6-astra", "author_effort": "high",
        "reviewer_model": "gpt-6.1-sol", "reviewer_effort": "high",
        "review_rounds": 3, "timeout_hours": 2,
        "git_name": "patchkeep", "git_email": "patchkeep@users.noreply.github.com",
        "launch_command": "", "done_command": "",
    },
    "notify": {"command": ""},
    "hosts": {"on_kev_command": "", "min_gap_hours": 2},
}


def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(CONFIG_PATH, "rb") as f:
            user = tomllib.load(f)
    except FileNotFoundError:
        user = {}
    for k, v in user.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


CFG = load_config()
STATE_DIR = os.path.expanduser(CFG["state_dir"])
LOG_DIR = STATE_DIR + "/logs"
RESULTS_DIR = STATE_DIR + "/results"
WORK_ROOT = CFG["work_root"]
PATH_ENV = ":".join(os.path.expanduser(p) for p in CFG["path"].split(":"))
OWNERS = {o.lower() for o in CFG["github"]["owners"]}
ACTIVE_DAYS = CFG["github"]["active_days"]
MAX_FIXERS = CFG["fix"]["max_parallel"]
FIX_TIMEOUT = int(CFG["fix"]["timeout_hours"] * 3600)
REVIEW_ROUNDS = CFG["fix"]["review_rounds"]
KEV_HOOK_MIN_GAP = int(CFG["hosts"]["min_gap_hours"] * 3600)
RETRY_HOURS = {"merged": 1, "reverted": 24, "blocked": 24, "failed": 24, "error": 6, "nofix": 24 * 7}
UPLOAD_RETRY = 3600
REVIEW_MAX_CHARS = 600_000

CVE_NOW = "https://cve.now"
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "bun.lock", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "poetry.lock", "Cargo.lock", "go.sum", "Gemfile.lock", "mix.lock",
    "uv.lock",
}
SKIP_PATH = re.compile(r"(^|/)(node_modules|vendor|\.worktrees|fixtures|__fixtures__|testdata|examples?)/")


# ---------------------------------------------------------------- helpers

def env(**extra):
    return dict(os.environ, PATH=PATH_ENV, GH_PROMPT_DISABLED="1", **extra)


def kill_group(pgid):
    """SIGKILL every process in the group. Nothing left is not an error; a group of only zombies can
    answer "not permitted" on macOS."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# A writer round's leftovers. kill_group ends what stayed in the round's session, but a process can start a
# session of its own and leave it. On Linux this process adopts every orphan of the round
# (PR_SET_CHILD_SUBREAPER), so all of them stay below it. On macOS an orphan goes to launchd, so the round's
# processes are found by their sandbox instead: sandbox_check asks the kernel what a process's sandbox allows.
PR_SET_CHILD_SUBREAPER = 36
SANDBOX_FILTER_PATH = 1
_SANDBOX_CHECK = []


def _signal(pid, sig):
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _proc_tree():
    """{parent pid: [(pid, state)]} for every process, from /proc."""
    tree = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name, "rb") as f:
                # The command name is in parentheses and may hold anything; the fields follow the last ")".
                fields = f.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        tree.setdefault(int(fields[1]), []).append((int(name), fields[0]))
    return tree


def _descendants():
    """(pid, state) of every process below this one."""
    tree, found, todo = _proc_tree(), [], [os.getpid()]
    while todo:
        for pid, state in tree.get(todo.pop(), ()):
            found.append((pid, state))
            todo.append(pid)
    return found


def _live_descendants():
    return [pid for pid, state in _descendants() if state != b"Z"]


def _reap_children():
    for pid, _ in _proc_tree().get(os.getpid(), ()):
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def _subreaper(on):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, int(on), 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, "prctl(PR_SET_CHILD_SUBREAPER): " + os.strerror(err))


def _sandbox_check():
    if not _SANDBOX_CHECK:
        fn = ctypes.CDLL("/usr/lib/libSystem.B.dylib").sandbox_check
        fn.restype = ctypes.c_int
        # Only the fixed arguments: the path is a variadic argument, which arm64 macOS passes on the stack,
        # and ctypes passes an argument past argtypes that way.
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        _SANDBOX_CHECK.append(fn)
    return _SANDBOX_CHECK[0]


def _sandboxed_writers(writes, mark):
    """This user's live processes whose sandbox lets them write in `writes` but not `mark`, a file made beside
    it for this check: the writer's sandbox, and no other process on the machine."""
    check = _sandbox_check()
    out = subprocess.run(["ps", "-U", str(os.getuid()), "-o", "pid=,stat="], capture_output=True, text=True,
                         timeout=60).stdout
    found = []
    for row in out.splitlines():
        cols = row.split()
        if len(cols) != 2 or cols[1].startswith("Z") or int(cols[0]) == os.getpid():
            continue
        pid = int(cols[0])
        if check(pid, None, 0) == 1 and check(pid, b"file-write-data", SANDBOX_FILTER_PATH, writes.encode()) == 0 \
                and check(pid, b"file-write-data", SANDBOX_FILTER_PATH, mark.encode()) == 1:
            found.append(pid)
    return found


def _kill_all(members, after_kill=lambda: None, passes=50):
    """SIGKILL every process members() returns. Each is stopped first and the list read again until no new
    one shows up, so none can start another between being found and being killed; then all are killed and
    the list is read again, until it is empty. A pid is kept only if members() still returns it once it is
    stopped: a stopped process can't exit, so its pid can't have gone to an unrelated process since.
    Raises when processes are still there after `passes` reads."""
    stopped = set()
    for _ in range(passes):
        found = [pid for pid in members() if pid not in stopped]
        if found:
            for pid in found:
                _signal(pid, signal.SIGSTOP)
            still = set(members())
            for pid in found:
                if pid in still:
                    stopped.add(pid)
                else:
                    _signal(pid, signal.SIGCONT)
            continue
        if not stopped:
            return
        for pid in stopped:
            _signal(pid, signal.SIGKILL)
        stopped = set()
        time.sleep(0.02)
        after_kill()
    raise RuntimeError("the writer left processes that could not be killed")


@contextlib.contextmanager
def _leftovers_killed(writes):
    """Around one writer round whose OS sandbox lets it write only in `writes`: when the round ends, kill
    every process it left, including one that started a session of its own. On Linux that is every process
    below this one, so the caller must have nothing else running."""
    system = platform.system()
    if not writes or system not in ("Linux", "Darwin"):
        yield
        return
    if system == "Linux":
        _subreaper(True)
        try:
            yield
        finally:
            try:
                _kill_all(_live_descendants, _reap_children)
                for _ in range(50):
                    if not _descendants():
                        break
                    _reap_children()
                    time.sleep(0.02)
            finally:
                _subreaper(False)
        return
    fd, mark = tempfile.mkstemp(prefix=".patchkeep-mark-", dir=os.path.dirname(writes))
    os.close(fd)
    try:
        yield
    finally:
        try:
            _kill_all(lambda: _sandboxed_writers(writes, mark))
        finally:
            os.remove(mark)


def run_in_own_group(cmd, timeout, cwd, stdin, environ, writes=None):
    """Run the untrusted writer in its own session, and SIGKILL everything it left in that session when it
    exits or times out, so no easy background child outlives the round and swaps a file or folder while
    the trusted side reads it. Output goes to files, not pipes: a leftover child holding a pipe would keep
    the read open until the timeout. A process that starts a session of its own leaves that session; with
    `writes`, the one folder the writer's sandbox lets it write, those are killed too (_leftovers_killed).
    Returns the last 1 MB of each stream."""
    def tail(f, limit=1_000_000):
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - limit))
        return f.read().decode("utf-8", "replace")

    with tempfile.TemporaryFile() as fin, tempfile.TemporaryFile() as fout, tempfile.TemporaryFile() as ferr:
        fin.write((stdin or "").encode())
        fin.seek(0)
        with _leftovers_killed(writes):
            try:
                p = subprocess.Popen(cmd, stdin=fin, stdout=fout, stderr=ferr, cwd=cwd, env=environ, start_new_session=True)
            except FileNotFoundError as ex:
                return 127, "", str(ex)
            try:
                rc = p.wait(timeout)
            except subprocess.TimeoutExpired:
                kill_group(p.pid)
                p.wait()
                return 124, "", "timeout"
            finally:
                kill_group(p.pid)
        return rc, tail(fout), tail(ferr)


def run(cmd, timeout=120, cwd=None, stdin=None, environ=None, own_group=False, writes=None):
    if own_group:
        return run_in_own_group(cmd, timeout, cwd, stdin, environ or env(), writes)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                           env=environ or env(), input=stdin)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def must(cmd, timeout=300, cwd=None):
    rc, so, se = run(cmd, timeout, cwd)
    if rc != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(cmd[:3]), (se or so).strip()[-200:]))
    return so


def gh_json(path, paginate=False):
    so = must(["gh", "api", path] + (["--paginate", "--slurp"] if paginate else []), 180)
    data = json.loads(so)
    return [x for page in data for x in page] if paginate else data


def http(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers=dict({"User-Agent": "patchkeep"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def now():
    return time.time()


def stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")


def dir_problem():
    """Why state_dir/work_root would break the sandbox boundary, or None. The trusted checkout and
    kill switches must sit under $HOME (denied to the agent); the agent's copy must sit outside it,
    on the same filesystem so it can be moved in before it is read."""
    home = os.path.realpath(HOME)
    state = os.path.realpath(STATE_DIR)
    os.makedirs(WORK_ROOT, exist_ok=True)
    work = os.path.realpath(WORK_ROOT)
    under = lambda p: p == home or p.startswith(home + os.sep)
    if not under(state):
        return "state_dir %s must be inside $HOME" % state
    if under(work):
        return "work_root %s must be outside $HOME" % work
    if os.stat(state).st_dev != os.stat(work).st_dev:
        return "work_root %s must be on the same filesystem as state_dir %s" % (work, state)
    return None


def killed(name):
    if name == "DISABLE_AUTOFIX" and not CFG["fix"]["enabled"]:
        return True
    if name == "DISABLE_AUTOMERGE" and not CFG["fix"]["automerge"]:
        return True
    return os.path.exists(STATE_DIR + "/" + name)


def load_state():
    try:
        with open(STATE_DIR + "/state.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state):
    tmp = STATE_DIR + "/state.json.tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE_DIR + "/state.json")


def log(msg):
    with open(LOG_DIR + "/watch.log", "a") as f:
        f.write("%s %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), msg))


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError):
        return False


def fixer_alive(fx, repo):
    """A fixer process for `repo` is running, or launch_command ran under 15 minutes ago and its
    fixer may not have started yet. Every step inside a fixer has its own timeout, so a live
    process always ends on its own."""
    age = now() - fx.get("started", 0)
    rc, so, _ = run(["pgrep", "-f", "patchkeep.py fix %s " % repo], 10)
    return (rc == 0 and so.strip() != "") or ("handle" in fx and age < 900)


def slug(repo):
    return repo.replace("/", "_")


# ---------------------------------------------------------------- inventory

def ignored(full_name):
    return any(fnmatch.fnmatchcase(full_name.lower(), pat.lower()) for pat in CFG["github"]["ignore"])


def active_repos():
    """Non-archived repos you can see, pushed in the last ACTIVE_DAYS. Forks are skipped unless
    include_forks is set: their dependencies usually track upstream. Repos owned by an account in
    `owners` are fixed; the rest are alert-only."""
    repos = gh_json("user/repos?per_page=100&affiliation=owner,collaborator,organization_member", paginate=True)
    cutoff = now() - ACTIVE_DAYS * 86400
    out = {}
    for r in repos:
        if r.get("archived") or (r.get("fork") and not CFG["github"]["include_forks"]) \
                or not r.get("pushed_at") or ignored(r["full_name"]):
            continue
        pushed = datetime.datetime.fromisoformat(r["pushed_at"].replace("Z", "+00:00")).timestamp()
        if pushed < cutoff:
            continue
        out[r["full_name"]] = {
            "branch": r["default_branch"],
            "pushed_at": r["pushed_at"],
            "owned": r["owner"]["login"].lower() in OWNERS,
        }
    return out


def uv_lock_as_requirements(text):
    pkgs = tomllib.loads(text).get("package", [])
    lines = ["%s==%s" % (p["name"], p["version"]) for p in pkgs
             if p.get("version") and "registry" in (p.get("source") or {})]
    return "\n".join(lines) + "\n", "requirements.txt"


def upload_lockfile(content, name):
    if name == "uv.lock":
        content, name = uv_lock_as_requirements(content)
    return http(CVE_NOW + "/api/stack", data=content.encode(), headers={"X-Lockfile-Name": name}, timeout=120)["id"]


def full_tree(full_name, branch):
    """Blobless clone listing for repos too big for the trees API."""
    d = tempfile.mkdtemp(prefix="patchkeep-tree-", dir=WORK_ROOT)
    try:
        must(["gh", "repo", "clone", full_name, d + "/r", "--", "--depth", "1", "--filter=blob:none",
              "--no-checkout", "--branch", branch], 600)
        so = git(d + "/r", "ls-tree", "-r", "HEAD")
        out = []
        for line in so.splitlines():
            meta, path = line.split("\t", 1)
            _, typ, sha = meta.split()
            out.append({"type": typ, "sha": sha, "path": path})
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def refresh_lockfiles(full_name, repo, prev, errors):
    """{path: {"blob", "stack", "unsupported"?, "tried"?}} for the default branch.
    Uploads new or changed lockfiles; retries failed uploads hourly; 422 means cve.now can't parse it."""
    tree = gh_json("repos/%s/git/trees/%s?recursive=1" % (full_name, repo["branch"]))
    entries = tree.get("tree", [])
    if tree.get("truncated"):
        entries = full_tree(full_name, repo["branch"])
    found = {}
    for e in entries:
        if e["type"] != "blob" or os.path.basename(e["path"]) not in LOCKFILES or SKIP_PATH.search(e["path"]):
            continue
        old = prev.get(e["path"]) or {}
        if old.get("blob") == e["sha"] and (old.get("stack") or old.get("unsupported")
                                             or now() - old.get("tried", 0) < UPLOAD_RETRY):
            found[e["path"]] = old
            continue
        entry = {"blob": e["sha"], "stack": None, "tried": now()}
        try:
            blob = gh_json("repos/%s/git/blobs/%s" % (full_name, e["sha"]))
            text = base64.b64decode(blob["content"]).decode("utf-8", "replace")
            entry["stack"] = upload_lockfile(text, os.path.basename(e["path"]))
        except urllib.error.HTTPError as ex:
            if ex.code == 422:
                entry["unsupported"] = True
            else:
                errors.append("%s: upload %s: %s" % (full_name, e["path"], ex))
        except Exception as ex:
            errors.append("%s: upload %s: %s" % (full_name, e["path"], ex))
        found[e["path"]] = entry
    return found


def needs_tree_refresh(rs, repo):
    if rs.get("pushed_at") != repo["pushed_at"] or "lockfiles" not in rs:
        return True
    return any(not lf.get("stack") and not lf.get("unsupported") and now() - lf.get("tried", 0) >= UPLOAD_RETRY
               for lf in rs["lockfiles"].values())


def ensure_dependabot_alerts(full_name, rstate):
    if rstate.get("alerts_enabled"):
        return
    rc, _, _ = run(["gh", "api", "-X", "PUT", "repos/%s/vulnerability-alerts" % full_name], 60)
    if rc == 0:
        rstate["alerts_enabled"] = True
        log("enabled dependabot alerts on " + full_name)


# ---------------------------------------------------------------- matching

def canonical(ids):
    ids = [i for i in ids if i]
    for i in ids:
        if i.upper().startswith("CVE-"):
            return i.upper()
    return ids[0] if ids else "?"


def stack_findings(full_name, path, sid):
    data = http("%s/stack?s=%s&format=json" % (CVE_NOW, sid), timeout=60)
    out = []
    for e in data.get("entries", []):
        m = e.get("matched") or {}
        exp = e.get("exploitation") or {}
        out.append({
            "repo": full_name, "path": path, "source": "cve.now",
            "eco": m.get("ecosystem"), "pkg": m.get("name"), "version": m.get("version"),
            "id": canonical([e.get("id")] + (e.get("aliases") or [])),
            "cvss": (e.get("severity") or {}).get("cvss"), "kev": bool(exp.get("kev")),
            "title": e.get("title") or "",
        })
    return out


def dependabot_findings(full_name):
    """Open Dependabot alerts, or [] when alerts are off or this token can't read them."""
    rc, so, se = run(["gh", "api", "--paginate", "--slurp",
                      "repos/%s/dependabot/alerts?state=open&per_page=100" % full_name], 180)
    if rc != 0:
        if re.search(r"HTTP 40[34]|disabled|Resource not accessible", se + so):
            return []
        raise RuntimeError("dependabot alerts: " + (se or so).strip()[-200:])
    alerts = [a for page in json.loads(so) for a in page]
    sev_cvss = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0}
    out = []
    for a in alerts:
        adv = a.get("security_advisory") or {}
        dep = a.get("dependency") or {}
        pkg = dep.get("package") or {}
        out.append({
            "repo": full_name, "path": dep.get("manifest_path"), "source": "dependabot",
            "eco": pkg.get("ecosystem"), "pkg": pkg.get("name"), "version": None,
            "id": canonical([adv.get("cve_id"), adv.get("ghsa_id")]),
            "cvss": (adv.get("cvss") or {}).get("score") or sev_cvss.get(adv.get("severity")),
            "kev": False, "title": adv.get("summary") or "",
            "patched": ((a.get("security_vulnerability") or {}).get("first_patched_version") or {}).get("identifier"),
        })
    return out


def fingerprint(f):
    return "%s|%s|%s" % (f["repo"], f["pkg"], f["id"])


def dedupe(findings):
    by = {}
    for f in findings:
        k = fingerprint(f)
        if k in by:
            by[k]["paths"].add(f["path"])
            by[k]["version"] = by[k]["version"] or f["version"]
            by[k]["patched"] = by[k].get("patched") or f.get("patched")
            by[k]["kev"] = by[k]["kev"] or f["kev"]
            continue
        by[k] = dict(f, paths={f["path"]})
    for f in by.values():
        f["paths"] = sorted(p for p in f["paths"] if p)
        f.pop("path", None)
    return by


def sev_word(f):
    c = f.get("cvss") or 0
    if f.get("kev"):
        return "actively exploited"
    return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"


# ---------------------------------------------------------------- hosts (optional hook)

def kev_ids():
    data = http(CVE_NOW + "/feed?filter=kev&format=json", timeout=60)
    return sorted({i["url"].rstrip("/").rsplit("/", 1)[-1] for i in data.get("items", [])})


def maybe_run_kev_hook(state, dry, errors):
    """When CISA adds actively exploited vulnerabilities, run hosts.on_kev_command (e.g. your
    machine patch script). KEV ids only count as seen once the hook actually starts."""
    cmd = CFG["hosts"]["on_kev_command"]
    if not cmd:
        return None
    try:
        ids = kev_ids()
    except Exception as ex:
        errors.append("kev feed: %s" % ex)
        return None
    seen = set(state.get("kev_seen", []))
    if not seen:
        state["kev_seen"] = ids
        return None
    new = [i for i in ids if i not in seen]
    hook = state.setdefault("kev_hook", {})
    if not new or pid_alive(hook.get("pid")) or now() - hook.get("started", 0) < KEV_HOOK_MIN_GAP:
        return None
    if dry:
        return "would run on_kev_command for new KEV entries: " + ", ".join(new[:5])
    out = LOG_DIR + "/kev-hook-%s.out" % stamp()
    p = subprocess.Popen(cmd, shell=True, stdout=open(out, "w"), stderr=subprocess.STDOUT,
                         start_new_session=True, env=env(PATCHKEEP_NEW_KEV=",".join(new)))
    hook.update({"pid": p.pid, "started": now(), "out": out, "reported": False})
    state["kev_seen"] = sorted(seen | set(ids))[-3000:]
    log("on_kev_command started for new KEV %s" % new[:10])
    return None


def kev_hook_report(state):
    """The last 3 non-empty lines the hook printed, once it has finished."""
    hook = state.get("kev_hook") or {}
    if not hook.get("out") or hook.get("reported") or pid_alive(hook.get("pid")):
        return []
    hook["reported"] = True
    try:
        text = open(hook["out"]).read().strip()
    except OSError:
        return []
    return [l for l in text.splitlines() if l.strip()][-3:]


# ---------------------------------------------------------------- watch pass

def own_open_pr(repo):
    """True if a security/ PR younger than a day is open (ours or another agent's). Older ones
    do not block; our own stale auto PRs are closed by the next fixer."""
    rc, so, _ = run(["gh", "pr", "list", "-R", repo, "--state", "open", "--json", "headRefName,createdAt"], 60)
    if rc != 0:
        return True
    for p in json.loads(so or "[]"):
        if not p["headRefName"].startswith("security/"):
            continue
        age = now() - datetime.datetime.fromisoformat(p["createdAt"].replace("Z", "+00:00")).timestamp()
        if age < 86400:
            return True
    return False


def notify(texts, state):
    """Print the lines (for cron mail or a wrapper that forwards stdout), and also pipe them to
    notify.command when it is set (a script that sends a text, Slack message, push, ...).
    Lines the command failed to send are kept in state and retried on the next pass."""
    if texts:
        print("\n".join(texts), flush=True)
    if not CFG["notify"]["command"]:
        return
    pending = state.get("notify_pending", []) + list(texts)
    rc, so, se = run(["/bin/sh", "-c", CFG["notify"]["command"]], 120, stdin="\n".join(pending) + "\n")
    if rc == 0:
        state["notify_pending"] = []
    else:
        state["notify_pending"] = pending[-200:]
        log("notify.command failed, will retry: %s" % (se or so).strip()[-200:])


def launch_fixer(repo, fs, fixes, state):
    """Start the fixer for one repo. By default it runs detached in the background. Set
    fix.launch_command to run it somewhere visible instead (a tmux window, an agent app thread);
    its stdout's last line is kept as a handle and passed to fix.done_command later."""
    items_path = LOG_DIR + "/items-%s-%s.json" % (slug(repo), stamp())
    with open(items_path, "w") as f:
        json.dump(fs, f, indent=1)
    logf = LOG_DIR + "/fix-%s-%s.log" % (slug(repo), stamp())
    fix_cmd = " ".join(shlex.quote(a) for a in ["env", "PATCHKEEP_CONFIG=" + os.path.abspath(CONFIG_PATH),
                                                 sys.executable, os.path.abspath(__file__), "fix", repo, items_path])
    rec = {"state": "running", "started": now(), "set": set_hash(fs), "log": logf, "items": items_path}
    template = CFG["fix"]["launch_command"]
    if template:
        cmd = template.format(repo=shlex.quote(repo), name=shlex.quote(repo.split("/", 1)[1]),
                              fix_cmd=shlex.quote(fix_cmd), log=shlex.quote(logf),
                              results=shlex.quote(RESULTS_DIR), slug=shlex.quote(slug(repo)))
        rc, so, se = run(["/bin/sh", "-c", cmd], 120)
        if rc == 0:
            rec["handle"] = (so.strip().splitlines() or [""])[-1]
            state.setdefault("handles", {})[items_path] = rec["handle"]
            log("fixer launched via launch_command for %s (%d findings) handle=%s" % (repo, len(fs), rec["handle"]))
            fixes[repo] = rec
            save_state(state)
            return
        log("launch_command failed (%s); running fixer in the background for %s" % ((se or so).strip()[-160:], repo))
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), "fix", repo, items_path],
                         stdout=open(logf, "w"), stderr=subprocess.STDOUT, start_new_session=True, env=env())
    rec["pid"] = p.pid
    log("fixer started for %s pid=%s (%d findings)" % (repo, p.pid, len(fs)))
    fixes[repo] = rec
    save_state(state)


def run_done_command(state, res):
    """Run fix.done_command for the run that produced `res` (matched by its items file)."""
    handle = state.get("handles", {}).pop(res.get("items") or "", None)
    template = CFG["fix"]["done_command"]
    if not template:
        return
    cmd = template.format(repo=shlex.quote(res["repo"]), status=shlex.quote(res["status"]),
                          pr=shlex.quote(res.get("pr") or ""), handle=shlex.quote(handle or ""))
    run(["/bin/sh", "-c", cmd], 60)


def set_hash(fs):
    return hashlib.sha1("\n".join(sorted(fingerprint(f) for f in fs)).encode()).hexdigest()[:12]


def watch(dry=False):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    lock = open(STATE_DIR + "/lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    state = load_state()
    first_run = "seen" not in state
    repos_state = state.setdefault("repos", {})
    seen = state.setdefault("seen", {})
    fixes = state.setdefault("fixes", {})
    errors, texts, reported_files = [], [], []

    try:
        repos = active_repos()
    except Exception as ex:
        repos = None
        errors.append("repo list: %s" % ex)

    findings, failed_repos = [], set()
    for full_name, repo in (repos or {}).items():
        rs = repos_state.setdefault(full_name, {})
        n_err = len(errors)
        try:
            if needs_tree_refresh(rs, repo):
                rs["lockfiles"] = refresh_lockfiles(full_name, repo, rs.get("lockfiles", {}), errors)
                rs["pushed_at"] = repo["pushed_at"]
            for path, lf in rs["lockfiles"].items():
                if lf.get("stack"):
                    findings += stack_findings(full_name, path, lf["stack"])
            if repo["owned"]:
                if not dry:
                    ensure_dependabot_alerts(full_name, rs)
            findings += dependabot_findings(full_name)
        except Exception as ex:
            errors.append("%s: %s" % (full_name, ex))
        if len(errors) > n_err:
            failed_repos.add(full_name)
        rs["owned"] = repo["owned"]
    if repos is not None:
        for gone in set(repos_state) - set(repos):
            repos_state.pop(gone)

    current = dedupe(findings)
    by_repo = {}
    for f in current.values():
        by_repo.setdefault(f["repo"], []).append(f)

    new_by_repo = {}
    for k, f in current.items():
        if k not in seen:
            seen[k] = now()
            new_by_repo.setdefault(f["repo"], []).append(f)
    if repos is not None:
        for k in list(seen):
            if k not in current and k.split("|", 1)[0] not in failed_repos:
                seen.pop(k)
    autofix = not killed("DISABLE_AUTOFIX")
    problem = dir_problem()
    if problem:
        autofix = False
        if state.get("dir_problem") != problem:
            texts.append("patchkeep is not fixing anything: " + problem)
        state["dir_problem"] = problem
    else:
        state.pop("dir_problem", None)
    if not first_run:
        for repo, fs in sorted(new_by_repo.items()):
            fs.sort(key=lambda f: (not f.get("kev"), -(f.get("cvss") or 0)))
            top = fs[0]
            more = " +%d more" % (len(fs) - 1) if len(fs) > 1 else ""
            owned = repos_state.get(repo, {}).get("owned")
            action = "Fixing it now." if owned and autofix else "Not auto-fixing (%s)." % (
                "autofix is off" if owned else "not one of your fix owners")
            texts.append("Vulnerable: %s uses %s %s (%s, %s)%s. %s" % (
                repo.split("/", 1)[1], top["pkg"], top.get("version") or "", top["id"], sev_word(top), more, action))

    if texts and not dry:
        notify(texts, state)
        texts = []
    # Fixer results first, so a finished run is closed out before its repo gets a new fixer.
    # One text per distinct outcome per repo.
    for name in sorted(os.listdir(RESULTS_DIR)):
        path = RESULTS_DIR + "/" + name
        if not name.endswith(".json"):
            continue
        try:
            res = json.load(open(path))
        except ValueError:
            continue
        if res.get("reported"):
            continue
        fx = fixes.setdefault(res["repo"], {})
        fx["outcome"] = res["status"]
        if not dry:
            run_done_command(state, res)
        key = "%s|%s" % (res["status"], res.get("set") or res.get("text"))
        if res["status"] == "merged" or fx.get("last_text_key") != key:
            texts.append(res["text"])
        fx["last_text_key"] = key
        reported_files.append((path, res))

    for repo, fx in fixes.items():
        if fx.get("state") == "running" and not fixer_alive(fx, repo):
            fx["state"] = "done"
            fx["ended"] = now()
    running = sum(1 for fx in fixes.values() if fx.get("state") == "running")
    for repo, fs in sorted(by_repo.items(), key=lambda kv: -max((f.get("cvss") or 0) for f in kv[1])):
        if not autofix or not repos_state.get(repo, {}).get("owned") or running >= MAX_FIXERS:
            continue
        fx = fixes.get(repo, {})
        if fx.get("state") == "running":
            continue
        retry = RETRY_HOURS.get(fx.get("outcome"), 24) * 3600
        if fx.get("set") == set_hash(fs) and now() - fx.get("ended", 0) < retry:
            continue
        if own_open_pr(repo):
            continue
        if dry:
            texts.append("would launch fixer for %s (%d findings)" % (repo, len(fs)))
            continue
        launch_fixer(repo, fs, fixes, state)
        running += 1

    texts += kev_hook_report(state)
    hint = maybe_run_kev_hook(state, dry, errors)
    if hint:
        texts.append(hint)

    if errors:
        log("errors: " + " | ".join(errors)[:3000])
        state["fail_streak"] = state.get("fail_streak", 0) + 1
    else:
        state["fail_streak"] = 0
        state["health_alerted"] = False
    if state["fail_streak"] >= 12 and not state.get("health_alerted"):
        state["health_alerted"] = True
        texts.append("patchkeep has had errors for an hour: %s" % errors[0][:160])

    state["last_run"] = datetime.datetime.now().isoformat(timespec="seconds")
    if dry:
        print("=== DRY RUN === repos=%d findings=%d errors=%d" % (len(repos or {}), len(current), len(errors)))
        for repo, fs in sorted(by_repo.items()):
            print("  %s (%d): %s" % (repo, len(fs), ", ".join(sorted("%s %s" % (f["pkg"], f["id"]) for f in fs))[:200]))
        for e in errors:
            print("  error: " + e[:200])
        for t in texts:
            print("  text: " + t)
        return
    # Print before saving: a crash between the two repeats a text rather than losing it.
    if texts or (CFG["notify"]["command"] and state.get("notify_pending")):
        notify(texts, state)
    for path, res in reported_files:
        res["reported"] = now()
        json.dump(res, open(path, "w"), indent=1)
    save_state(state)


# ---------------------------------------------------------------- fixer

REVIEW_ASK = "Review this PR. Reply AGREE, or a numbered list of findings, each with file:line and the failing behavior."


def git(repo_dir, *args, timeout=300):
    """git in a trusted checkout only. Hooks and fsmonitor are off as a second guard."""
    return must(["git", "-C", repo_dir, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]
                + list(args), timeout)


def git_bytes(repo_dir, *args, timeout=300):
    """git() with the output as bytes. Text mode would turn a bare carriage return into a newline, and a
    line that git and the checks see as one would then be two for them but one for a YAML or pip parser."""
    cmd = ["git", "-C", repo_dir, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"] + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env())
    except subprocess.TimeoutExpired:
        raise RuntimeError("git %s timed out" % args[0])
    if p.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (args[0], p.stderr.decode("utf-8", "replace").strip()[-200:]))
    return p.stdout


def raw_diff(repo_dir, *args, paths=False):
    """`git diff` for every check and for the reviewer. A .gitattributes in the repo (-diff, binary, diff=
    with a textconv or external driver) must not decide what they get to see, so each file is diffed as
    plain text. Renames are a delete plus an add. Invalid UTF-8 in file content is replaced, not fatal.
    With `paths=True` the output is file names, which must stay exact: an invalid name is an error, since
    a mangled one would make a check read a file that is not there. Names are written as they are, not
    quoted with octal escapes."""
    out = git_bytes(repo_dir, "-c", "core.quotePath=false", "diff", "--text", "--no-textconv", "--no-ext-diff",
                    "--no-renames", *args)
    return out.decode("utf-8") if paths else out.decode("utf-8", "replace")


def changed_paths(repo_dir, base):
    """Every path the branch changes against the base. Taken from the local commit: GitHub's list of a
    pull request's files stops at about 100, so a bigger change could hide a file from the merge rules."""
    return [p for p in raw_diff(repo_dir, "--name-only", "-z", "origin/%s...HEAD" % base, paths=True).split("\0") if p]


# Git writes a name holding one of these in quotes even with core.quotePath off. A diff header with one is
# not parsed here (the checks would read the path with its quotes), so a branch that touches such a name is
# refused. A dependency fix never needs one.
GIT_QUOTED = re.compile(r'["\\\x00-\x1f\x7f]')


def quoted_names(paths):
    return [p for p in paths if GIT_QUOTED.search(p)]


def diff_lines(text):
    """The lines of git output, split on newlines only. str.splitlines() also breaks at U+0085, U+2028,
    U+2029 and others, so a file name or a line of content holding one followed by `diff --git a/x b/x`
    would start a section git never wrote, and the lines after it would be checked as another file."""
    return [l[:-1] if l.endswith("\r") else l for l in text.split("\n")]


BIG_LOCK_SECTION = 100_000
HASH_LINE = re.compile(r"""^[-+]\s*"?(integrity|checksum|hash|shasum)"?\s*[:=]\s*\S+[,]?\s*$|^[-+]\s*(--hash=)?sha\d+[:-][A-Za-z0-9+/=]+\s*\\?\s*$""")
REGISTRY_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org", "pypi.org",
                  "static.crates.io", "crates.io", "index.crates.io", "proxy.golang.org", "rubygems.org",
                  "repo.hex.pm", "github.com", "codeload.github.com"}


def link_problems(repo_dir, base):
    """Paths whose new version on the branch is a symbolic link, from `git diff --raw`. A dependency fix
    never needs one, and the trusted side opens changed lockfiles, so a link planted by the writer could
    make it read a file under $HOME."""
    out = []
    for line in diff_lines(raw_diff(repo_dir, "--raw", "origin/%s...HEAD" % base)):
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) >= 2 and fields[1] == "120000":
            out.append(path)
    return out


# CI runs a pushed branch with the repo's secrets, and a workflow or local action the writer edited is
# what it would run. A dependency fix never needs to touch anything under .github, so any edit there is
# refused. Matched without regard to case: the writer's disk may not tell `.GitHub` from `.github`.
CI_PATH = re.compile(r"^\.github/", re.I)


def branch_problem(repo_dir, base):
    """Why the local commit must not be pushed, in words, or None. Everything here runs before any push,
    because CI would run the pushed branch. Quoted names come first: a diff header with one is not parsed
    by the checks below."""
    paths = changed_paths(repo_dir, base)
    quoted = quoted_names(paths)
    if quoted:
        return "it adds or changes a file whose name git has to quote (%s)" % ", ".join(repr(p) for p in quoted[:3])
    links = link_problems(repo_dir, base)
    if links:
        return "it adds or changes a symbolic link (%s)" % ", ".join(links[:3])
    ci = [p for p in paths if CI_PATH.match(p)]
    if ci:
        return "it edits files under .github (%s)" % ", ".join(ci[:3])
    return None


def split_diff(diff):
    sections, cur = [], None
    for line in diff_lines(diff):
        if line.startswith("diff --git"):
            cur = [line.split(" b/", 1)[-1], [line]]
            sections.append(cur)
        elif cur:
            cur[1].append(line)
    return [(path, "\n".join(lines)) for path, lines in sections]


NPM_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json"}
# npm lockfiles copy each package's "funding" field (a URL, an object, or a list of either). Those are
# donation links, never download sources, so they must not trip the foreign-host check.
NPM_FUNDING_START = re.compile(r"""^\s*"funding"\s*:\s*(.*)$""")
# npm's deprecation notices and license fields are free text from the package author and often link to
# a website. The package's real source is on its own "resolved" line, which is still checked, and the
# parsed lock backs this up. pnpm and Yarn lockfiles are only read line by line, and in YAML a line that
# starts as a notice can go on to set the source, so their notices are read like any other line.
NPM_NOTE = re.compile(r'^\+\s*"(?:deprecated|license)"\s*:\s*"')


def npm_funding_lines(lines):
    """Indexes of diff lines that sit inside an npm "funding" field of the new file. A block cut off at a
    hunk start is not recognised, so its URLs are still checked."""
    skip, depth = set(), 0
    for i, line in enumerate(lines):
        if line[:1] not in "+ ":
            if line.startswith("@@"):
                depth = 0
            continue
        body = line[1:]
        if depth:
            skip.add(i)
            depth += body.count("{") + body.count("[") - body.count("}") - body.count("]")
            depth = max(depth, 0)
            continue
        m = NPM_FUNDING_START.match(body)
        if m:
            skip.add(i)
            rest = m.group(1)
            depth = max(rest.count("{") + rest.count("[") - rest.count("}") - rest.count("]"), 0)
    return skip


GIT_SHORTHAND = re.compile(r"(?<![\w/.-])(?:github|gitlab|bitbucket|gist):[\w.-]+")
# `git@host:path`. Yarn writes its own protocols the same way (`x@npm:1.0.0`), and those are not hosts.
SCP_URL = re.compile(r"(?<![\w/.:-])[\w.-]+@(?!(?:npm|patch|workspace|file|portal|link|exec|virtual):)([\w.-]+):[\w./~-]")
URL_HOST = re.compile(r"([a-z][a-z0-9+.-]*)://([^/\s\"']+)", re.I)
# Cargo names crates.io by its index on GitHub. Any other GitHub address in a lockfile is a checkout or a
# source tarball, which runs that code's build and install scripts like any other foreign source.
CRATES_INDEX = re.compile(r"registry\+https://github\.com/rust-lang/crates\.io-index(?=[\"')\s]|\Z)")
JSON_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"}
TOML_LOCKS = {"uv.lock", "poetry.lock", "Cargo.lock"}
# What hides text from a scan of lines in the formats read line by line: an escape, in YAML also a tag
# (`!!binary` turns base64 into the text) outside a comment line, and in a POM a character reference or
# an entity.
YAML_HIDDEN = re.compile(r"^(?!\s*#).*?(?:\\|!)")
HIDDEN_TEXT = {"pnpm-lock.yaml": YAML_HIDDEN, "yarn.lock": YAML_HIDDEN,
               "pom.xml": re.compile(r"&#|<!ENTITY", re.I)}
BACKSLASH = re.compile(r"\\")
# Mix reads mix.lock by evaluating it as Elixir, so each line of it must be plain data: strings without
# escapes or interpolation, atoms, keyword keys, numbers, true/false/nil and brackets. Anything else (a
# call, `<>`, a sigil) is code that runs whenever mix reads the lock.
MIX_TOKEN = re.compile(r'\s+|"[^"\\#]*":?|:"[^"\\#]*"|:[A-Za-z_]\w*[?!]?|[A-Za-z_]\w*:(?=\s)|(?:true|false|nil)\b'
                       r'|-?\d+(?:\.\d+)?\b|%\{|[{}\[\],]|=>')


def named_sources(text):
    """The foreign sources a piece of lockfile text names: a URL whose host is not a release host, in any
    scheme (git://, ssh:// and git+https:// pull code too), a git URL on any host, the shorthand
    `github:user/repo`, and the scp form `git@host:path`. The host is the whole text up to the first
    slash, so `registry.npmjs.org@evil.example` or a port is not taken for an allowed host."""
    text = CRATES_INDEX.sub("", text)
    found = set()
    for scheme, host in URL_HOST.findall(text):
        scheme, host = scheme.lower(), host.lower()
        if host not in RELEASE_HOSTS or scheme.startswith("git"):
            found.add(host if scheme in ("http", "https") else "%s://%s" % (scheme, host))
    found |= {m.group(0) for m in GIT_SHORTHAND.finditer(text)}
    found |= {h.lower() for h in SCP_URL.findall(text)}
    return found


def mix_data(line):
    pos = 0
    while pos < len(line):
        m = MIX_TOKEN.match(line, pos)
        if not m:
            return False
        pos = m.end()
    return True


def lock_strings(name, text):
    """(field, string) for every string in a lockfile Python reads, keys included and escapes decoded,
    `field` being the key it sits under. The funding links, deprecation notes and license fields of npm's
    package entries and poetry's package descriptions are not sources and are left out. Raises ValueError when the text
    does not parse."""
    doc = json.loads(text) if name in JSON_LOCKS else tomllib.loads(text)
    if name in NPM_LOCKFILES and isinstance(doc, dict) and isinstance(doc.get("packages"), dict):
        doc = dict(doc, packages={k: {f: x for f, x in v.items() if f not in ("funding", "deprecated", "license")}
                                  if isinstance(v, dict) else v for k, v in doc["packages"].items()})
    out, stack = set(), [("", doc)]
    while stack:
        field, value = stack.pop()
        if isinstance(value, dict):
            for k, v in value.items():
                out.add((field, k))
                stack.append((k, v))
        elif isinstance(value, list):
            stack.extend((field, v) for v in value)
        elif isinstance(value, str) and not (name == "poetry.lock" and field == "description"):
            out.add((field, value))
    return out


def read_sources(repo_dir, base, path, name, section):
    """The foreign sources in what the tools read from one changed lockfile, against its text in the base:
    for JSON and TOML, strings that are new as decoded; for a requirements file, the lines pip joins, each
    new one also having to name only a package on the index (an option such as `-r other.txt` pulls in a
    file this check never reads)."""
    if name not in JSON_LOCKS | TOML_LOCKS | {"requirements.txt"}:
        return set()
    new = blob(repo_dir, "HEAD", path)
    if new is None:
        return set() if "\ndeleted file mode" in section else {"a %s that is not UTF-8 text" % name}
    old = blob(repo_dir, "origin/" + base, path)
    found = set()
    if name == "requirements.txt":
        before = set(pip_logical_lines(old)) if old is not None else set()
        for line in pip_logical_lines(new):
            if line and line not in before:
                found |= named_sources(line)
                if not plain_requirement(line):
                    found.add("a pip line that is not a package on the index: " + line[:80])
        return found
    try:
        fresh = lock_strings(name, new)
    except (ValueError, RecursionError):
        return {"a %s that does not parse" % name}
    try:
        fresh -= lock_strings(name, old) if old is not None else set()
    except (ValueError, RecursionError):
        pass
    for _, text in fresh:
        found |= named_sources(text)
    return found


def foreign_sources(diff, repo_dir=None, base=None):
    r"""The foreign sources a branch adds to its lockfiles (see named_sources), sorted: those on added diff
    lines, and given `repo_dir` and `base`, those in what the tools read. A line can hide a URL behind an
    escape (`https:\/\/` in JSON, `\u002F` or a multi-line string in TOML, a trailing backslash in a
    requirements file), so a format Python reads is compared as decoded strings, a requirements file as
    the lines pip joins, and in the formats read line by line a line with an escape counts as foreign.
    Mix runs mix.lock as Elixir, so a line of it that is not plain data counts too."""
    found = set()
    for path, text in split_diff(diff):
        name = os.path.basename(path) if os.path.basename(path) in LOCKFILES else None
        if not name:
            continue
        lines = diff_lines(text)
        skip = npm_funding_lines(lines) if name in NPM_LOCKFILES else set()
        hunk = False
        for i, line in enumerate(lines):
            hunk = hunk or line.startswith("@@")
            if not line.startswith("+") or (not hunk and line.startswith("+++ ")):
                continue
            if i not in skip and not (name in NPM_LOCKFILES and NPM_NOTE.match(line)):
                found |= named_sources(line[1:])
            if name == "mix.lock":
                if not mix_data(line[1:]):
                    found.add("Elixir code in mix.lock")
            elif name not in JSON_LOCKS | TOML_LOCKS | {"requirements.txt"} and HIDDEN_TEXT.get(name, BACKSLASH).search(line[1:]):
                found.add("an escape or a tag in " + name)
        if repo_dir is not None:
            found |= read_sources(repo_dir, base, path, name, text)
    return sorted(found)


def review_diff(repo_dir, base):
    """The branch diff for review, from the trusted checkout. Returns (diff, foreign hosts);
    diff is None if it is too big to review even after reduce_diff."""
    diff = raw_diff(repo_dir, "origin/%s...HEAD" % base)
    return reduce_diff(diff), foreign_sources(diff, repo_dir, base)


def reduce_diff(diff):
    """The diff unchanged if it fits. Otherwise each lockfile section bigger than BIG_LOCK_SECTION
    loses its unchanged context and integrity-hash lines; every other changed line stays."""
    if len(diff) <= REVIEW_MAX_CHARS:
        return diff
    parts = []
    for path, text in split_diff(diff):
        if os.path.basename(path) in LOCKFILES and len(text) > BIG_LOCK_SECTION:
            kept = [l for l in diff_lines(text)[1:] if l[:1] in "+-" and not HASH_LINE.match(l)]
            parts.append(diff_lines(text)[0] + "\n(large lockfile: unchanged context and integrity hashes omitted; every other changed line shown)\n" + "\n".join(kept))
        else:
            parts.append(text)
    text = "\n".join(parts)
    return text if len(text) <= REVIEW_MAX_CHARS else None


def sol_review(body, diff, history):
    prompt = "%s\n\nPR description:\n%s\n\n%sDiff:\n%s" % (REVIEW_ASK, body, history, diff)
    rdir = tempfile.mkdtemp(prefix="patchkeep-review-", dir=WORK_ROOT)
    out = rdir + "/verdict.txt"
    try:
        rc, so, se = run(["codex", "exec", "-m", CFG["fix"]["reviewer_model"], "-c", "model_reasoning_effort=" + CFG["fix"]["reviewer_effort"], "-s", "read-only",
                          "--skip-git-repo-check", "-C", rdir, "-o", out, "-"], 1800, cwd=rdir, stdin=prompt)
        if rc != 0 or not os.path.exists(out):
            raise RuntimeError("reviewer failed (rc=%s): %s" % (rc, (se or so).strip()[-200:]))
        verdict = open(out).read().strip()
    finally:
        shutil.rmtree(rdir, ignore_errors=True)
    first = verdict.splitlines()[0].strip().strip("*.` ").upper() if verdict else ""
    return first == "AGREE", verdict


# Matches a file or folder of any case at any depth, with no trailing slash. rsync's `.git/` matches a
# folder spelled exactly that way, but on a case-insensitive disk (macOS) a writer-made `.GIT/config`
# lands in the trusted `.git/config`, and a `.git` file (`gitdir: ...`) is not a folder at all.
GIT_EXCLUDE = "[.][Gg][Ii][Tt]"
DIR_EXCLUDES = ["node_modules/", ".venv/", "venv/", "__pycache__/", ".pnpm-store/", ".next/",
                ".turbo/", ".cache/", ".parcel-cache/", ".pytest_cache/", ".mypy_cache/", "target/"]
GIT_SETTINGS = {".gitattributes", ".gitmodules", ".lfsconfig"}
ABSENT = object()


class WriterRefused(RuntimeError):
    """The writer did something that ends the run without a push. The message finishes "the writer ..."."""


def sync_tree(src, dst):
    """Mirror src's working files onto dst. Never copies or touches .git; symlinks stay links.
    --checksum: the default size-and-mtime check skips an edit that keeps a file's size and mtime."""
    cmd = ["rsync", "-a", "--checksum", "--delete", "--no-specials", "--no-devices", "--exclude", GIT_EXCLUDE]
    for e in DIR_EXCLUDES:
        cmd += ["--exclude", e]
    must(cmd + [src.rstrip("/") + "/", dst.rstrip("/") + "/"], 900)


def fold_name(name):
    """A file name as git on a case-insensitive disk would see it: composed form, no invisible format
    characters (HFS+ ignores them), case-folded."""
    name = unicodedata.normalize("NFC", name)
    return "".join(c for c in name if unicodedata.category(c) != "Cf").casefold()


def scan_tree(root):
    """(links {path: target}, git settings {path: bytes, or None if not a plain file}, git-like names) of a
    tree, walked the way sync_tree sees it: never through a link, not into the folders rsync skips. A real
    `.git` folder is skipped like rsync skips it; any other entry that folds to `.git` is reported."""
    links, settings, git_names = {}, {}, []

    def broken(err):
        raise err
    for folder, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=broken):
        for name in dirs + files:
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            is_link = os.path.islink(path)
            if is_link:
                links[rel] = os.readlink(path)
            folded = fold_name(name)
            if folded == ".git":
                if name != ".git" or is_link or name not in dirs:
                    git_names.append(rel)
            elif folded in GIT_SETTINGS:
                data = None
                if stat.S_ISREG(os.lstat(path).st_mode):
                    with open(path, "rb") as f:
                        data = f.read()
                settings[rel] = data
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d))
                   and d != ".git" and d + "/" not in DIR_EXCLUDES]
    return links, settings, git_names


def copy_problems(copy, trusted):
    """What the writer did to its copy that must stop it reaching the trusted checkout, as phrases that
    finish "the writer ...": git metadata of any spelling, any change to .gitattributes, .gitmodules or
    .lfsconfig (a `-diff` attribute hides content from every diff, and the other two reach git itself),
    and links the trusted checkout does not already have. A link the checks never look at would let a
    later step read or write a file outside the checkout."""
    links, settings, git_names = scan_tree(copy)
    base_links, base_settings, _ = scan_tree(trusted)
    out = ["created git metadata (%s)" % p for p in sorted(git_names)]
    out += ["changed git settings (%s)" % p for p in sorted(set(settings) | set(base_settings))
            if settings.get(p, ABSENT) != base_settings.get(p, ABSENT)]
    out += ["added or changed a symbolic link (%s)" % p for p, target in sorted(links.items())
            if base_links.get(p) != target]
    return out


def snapshot_tree(src, dst):
    """A private, complete copy of src for checking. Unlike sync_tree it keeps git-named entries so
    copy_problems can see them, and it starts from nothing each time."""
    rmtree_force(dst)
    os.makedirs(dst)
    cmd = ["rsync", "-a", "--no-specials", "--no-devices"]
    for e in DIR_EXCLUDES:
        cmd += ["--exclude", e]
    must(cmd + [src.rstrip("/") + "/", dst.rstrip("/") + "/"], 900)


def collect_agent_copy(work_fd, agent_name, holding, trusted):
    """Move the agent's copy (`agent_name`, inside the folder `work_fd` is open on) under HOME, which the
    sandbox cannot touch, before reading it, so a leftover process cannot swap it for a symlink mid-sync.
    A process that kept a handle on the folder can still change it after the move, so it is copied once
    into a snapshot nothing else holds, and that snapshot is what gets checked and then mirrored onto the
    trusted checkout. The agent's copy goes back for the next round. Both moves go through the work
    folder's handle, so a work path the writer has since pointed elsewhere cannot make them touch another
    folder. Returns copy_problems(); with any, nothing was synced."""
    snapshot = holding + "-snapshot"
    try:
        os.rename(agent_name, holding, src_dir_fd=work_fd)
    except OSError as ex:
        raise RuntimeError("cannot move the agent copy into the state dir (%s). Set work_root to a "
                           "folder outside $HOME on the same filesystem as state_dir." % ex)
    try:
        if os.path.islink(holding) or not os.path.isdir(holding):
            raise WriterRefused("replaced its copy of the repo with a link or a file")
        snapshot_tree(holding, snapshot)
    finally:
        os.rename(holding, agent_name, dst_dir_fd=work_fd)
    try:
        problems = copy_problems(snapshot, trusted)
        if not problems:
            sync_tree(snapshot, trusted)
    finally:
        rmtree_force(snapshot)
    return problems


OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def open_private_dir(parent_fd, name):
    """A handle on the folder `name` inside the folder `parent_fd` is open on, made if it is missing. A
    link or plain file the writer put in its place is removed, never followed. Every step goes through the
    parent handle, so renaming or relinking the parent's path afterwards changes nothing here."""
    try:
        return os.open(name, OPEN_DIR, dir_fd=parent_fd)
    except OSError:
        try:
            found = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            found = None
        if found and stat.S_ISDIR(found.st_mode):
            raise
        if found:
            os.unlink(name, dir_fd=parent_fd)
    os.mkdir(name, 0o755, dir_fd=parent_fd)
    return os.open(name, OPEN_DIR, dir_fd=parent_fd)


def read_agent_result(dir_fd, name):
    """The writer's result JSON in the folder `dir_fd` is open on, or None. The file sits where the agent
    can write, so a link there must not make this process read a file under HOME and a named pipe must not
    make it wait forever: only a regular file is opened, and without blocking."""
    try:
        if not stat.S_ISREG(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
            return None
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    with os.fdopen(fd) as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        try:
            res = json.loads(f.read(2_000_000))
        except ValueError:
            return None
    return res if isinstance(res, dict) else None


def work_identity(work_fd):
    st = os.fstat(work_fd)
    return st.st_dev, st.st_ino


def check_work(work, identity):
    """The work folder must still be the folder made for this run, or the writer's results are not to be
    trusted. This only tells the run to stop. What the trusted side does inside the folder goes through the
    handle, because a path checked here can be swapped a moment later."""
    try:
        st = os.lstat(work)
    except OSError:
        st = None
    if st is None or not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != identity:
        raise WriterRefused("replaced its work folder")


def _chmod_nofollow(name, dir_fd, mode):
    """chmod `name` in the folder `dir_fd` unless it is a link. Linux has no no-follow chmod, so the file is
    opened as an O_PATH handle (which is the link itself, when it is one) and changed through that."""
    if os.chmod in os.supports_follow_symlinks:
        os.chmod(name, mode, dir_fd=dir_fd, follow_symlinks=False)
    elif hasattr(os, "O_PATH"):
        fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=dir_fd)
        try:
            if not stat.S_ISLNK(os.fstat(fd).st_mode):
                os.chmod("/proc/self/fd/%d" % fd, mode)
        finally:
            os.close(fd)


def _unlock(name, dir_fd, st):
    """Make `name` (in the folder `dir_fd`, last seen as `st`) deletable: clear its file flags (macOS `uchg`)
    and give a folder owner access. Never acts on a link or on a link's target."""
    if stat.S_ISLNK(st.st_mode):
        return
    if getattr(st, "st_flags", 0) and hasattr(os, "chflags") and os.chflags in os.supports_follow_symlinks:
        # chflags takes no folder handle, so the process steps into the folder to name the file alone.
        here = os.open(".", os.O_RDONLY)
        try:
            os.fchdir(dir_fd)
            os.chflags(name, 0, follow_symlinks=False)
        except OSError:
            pass
        finally:
            os.fchdir(here)
            os.close(here)
    if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_IRWXU != stat.S_IRWXU:
        _chmod_nofollow(name, dir_fd, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)


def _remove(name, dir_fd):
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    _unlock(name, dir_fd, st)
    if not stat.S_ISDIR(st.st_mode):
        os.unlink(name, dir_fd=dir_fd)
        return
    try:
        fd = os.open(name, OPEN_DIR, dir_fd=dir_fd)
    except OSError:
        os.unlink(name, dir_fd=dir_fd)    # swapped for a link since it was looked at: drop the link
        return
    try:
        if not os.path.samestat(os.fstat(fd), st):
            return
        for entry in os.listdir(fd):
            try:
                _remove(entry, fd)
            except (OSError, RecursionError):
                pass
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=dir_fd)


def rmtree_force(path):
    """Remove a folder tree, including one with read-only folders or immutable files (test runs leave
    those behind: Go's module cache has no writable folder). Every step names an entry inside a folder
    that is already open, so a process that swaps a folder for a link while this runs cannot make it
    change or delete anything outside the tree. Links are removed and never followed. What cannot be
    removed is left."""
    parent, name = os.path.split(os.path.abspath(path))
    try:
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        _remove(name, dir_fd)
    except (OSError, RecursionError):
        pass    # missing, or nested deeper than the stack or the open-file limit allows: left, not fatal
    finally:
        os.close(dir_fd)


def discard_work(work, trusted_root):
    """Delete the work folder. The writer can still change it, and a process it left running can swap a
    folder in it for a link at any moment. So it is first renamed into the trusted root, which the sandbox
    cannot touch (the same move collect_agent_copy makes), and deleted there. When it can't be moved it
    stays: deleting it through a path the writer can change is worse than leaving it."""
    moved = os.path.join(trusted_root, "work-discarded")
    try:
        os.rename(work, moved)
    except FileNotFoundError:
        return
    except OSError as ex:
        log("left %s in place, cannot move it out of the writer's reach: %s" % (work, ex))
        return
    rmtree_force(moved)


def author(work, work_fd, work_id, agent_dir, prompt, result_name):
    """Run the fixer agent in Codex's OS sandbox. It sees a plain copy of the repo with no .git, can write
    only under the work dir, and every read or write under the real HOME is denied, so GitHub and git
    credentials and the trusted checkout are unreachable. Its network reaches public hosts for package
    installs, through Codex's own proxy, and nothing local.
    `work` is the path made once at the start and `work_fd` an open handle on it: everything the trusted
    side does inside the folder goes through the handle, which a link put at the path later cannot
    redirect. Returns its result JSON."""
    check_work(work, work_id)
    try:
        _remove(result_name, work_fd)
    except FileNotFoundError:
        pass
    os.close(open_private_dir(work_fd, "home"))
    os.close(open_private_dir(work_fd, "tmp"))
    home = work + "/home"
    environ = env(HOME=home, CODEX_HOME=HOME + "/.codex", XDG_CACHE_HOME=home + "/.cache",
                  GIT_CONFIG_GLOBAL="/dev/null", GH_CONFIG_DIR=home + "/gh", TMPDIR=work + "/tmp")
    for k in ("GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK"):
        environ.pop(k, None)
    # ":slash_tmp" is read-only because the default work_root is /tmp, where the reviewer's folder (its
    # verdict is read back from there) and other runs' folders live. The writer's own temp files go to
    # TMPDIR, inside `work`, which --add-dir makes writable.
    # The network goes through Codex's own proxy (features.network_proxy), which lets commands reach public
    # hosts and nothing local. Without it the commands could reach any Unix socket and localhost: through
    # a terminal multiplexer's socket (macOS) or the user's service manager over D-Bus (Linux) a command ran
    # a program outside the sandbox that wrote under $HOME (tested with Codex 0.163 and 0.166).
    rc, so, se = run(["codex", "exec", "-m", CFG["fix"]["author_model"], "-c", "model_reasoning_effort=" + CFG["fix"]["author_effort"],
                      "-c", 'default_permissions="vulnfix"',
                      "-c", 'permissions.vulnfix.extends=":workspace"',
                      "-c", 'permissions.vulnfix.filesystem={"%s"="deny",":slash_tmp"="read"}' % HOME,
                      "-c", "permissions.vulnfix.network.enabled=true", "-c", "features.network_proxy=true",
                      "-c", 'permissions.vulnfix.network.domains={"*"="allow"}',
                      "--add-dir", work, "--skip-git-repo-check", "-C", agent_dir, "-"],
                     FIX_TIMEOUT, cwd=agent_dir, stdin=prompt, environ=environ, own_group=True, writes=work)
    print(so[-20000:], se[-5000:], flush=True)
    check_work(work, work_id)
    res = read_agent_result(work_fd, result_name)
    if res is None:
        raise RuntimeError("fixer agent wrote no result (rc=%s)" % rc)
    return res


def pr_workflows(repo_dir):
    """Paths of workflows that run on pull requests, e.g. {'.github/workflows/ci.yml'}."""
    wf = os.path.join(repo_dir, ".github", "workflows")
    out = set()
    for name in os.listdir(wf) if os.path.isdir(wf) else []:
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(wf, name), errors="replace") as f:
                if re.search(r"\bpull_request(_target)?\b", f.read()):
                    out.add(".github/workflows/" + name)
    return out


def has_workflows(repo_dir):
    return os.path.isdir(os.path.join(repo_dir, ".github", "workflows"))


def paged(path, key):
    so = must(["gh", "api", "--paginate", "--slurp", path], 180)
    return [x for page in json.loads(so) for x in page.get(key, [])]


def outcome_of(r):
    if r["status"] != "completed":
        return "pending"
    return "pass" if r["conclusion"] in ("success", "neutral") else "skip" if r["conclusion"] == "skipped" else "fail"


def commit_checks(repo, sha):
    """(outcomes, runs, jobs) for every check run, commit status and Actions run on exactly `sha`.
    `runs` is {workflow path: [(run outcome, check suite id)]} and `jobs` is {check suite id: [job
    outcomes]}. A run and the jobs it started share a check suite, which is what shows whether a workflow's
    jobs really ran or were all skipped."""
    out, runs, jobs = [], {}, {}
    for r in paged("repos/%s/commits/%s/check-runs?per_page=100" % (repo, sha), "check_runs"):
        out.append(outcome_of(r))
        jobs.setdefault((r.get("check_suite") or {}).get("id"), []).append(outcome_of(r))
    latest = {}
    for st in gh_json("repos/%s/commits/%s/statuses?per_page=100" % (repo, sha), paginate=True):
        latest.setdefault(st["context"], st["state"])
    for state in latest.values():
        out.append({"success": "pass", "pending": "pending"}.get(state, "fail"))
    for r in paged("repos/%s/actions/runs?head_sha=%s&per_page=100" % (repo, sha), "workflow_runs"):
        runs.setdefault(r.get("path", "").split("@", 1)[0], []).append((outcome_of(r), r.get("check_suite_id")))
        # A run that succeeded because every job skipped tested nothing, so on its own it is no pass.
        o = outcome_of(r)
        out.append("skip" if o == "pass" and "pass" not in jobs.get(r.get("check_suite_id"), ()) else o)
    return out, runs, jobs


def unproven_workflows(required, runs, jobs):
    """Required workflows with no run that succeeded and started a job that passed. A workflow whose jobs
    were all skipped (a path filter, an `if:`) succeeds without testing anything. Skipped jobs inside a
    run that also has a passing job are fine: deploy jobs skip on pull requests."""
    return sorted(w for w in required if not any(
        o == "pass" and suite is not None and "pass" in jobs.get(suite, ()) for o, suite in runs.get(w, ())))


def checks_state(repo, sha, required, settle=180):
    """'pass', 'none', 'skipped', 'fail' or 'error' for everything reported on exactly `sha`.
    `required` is the set of workflow paths that must each have a run that passed. Waits at least `settle`
    seconds and for two identical polls. 'skipped' is a settled result in which a required workflow ran
    but proved nothing. 'none' only when nothing is required and nothing ran."""
    start, prev = now(), None
    while True:
        try:
            got, runs, jobs = commit_checks(repo, sha)
            got = sorted(got)
        except Exception:
            return "error"
        if "fail" in got:
            return "fail"
        waited = now() - start
        if waited >= settle and got == prev and required <= set(runs) and "pending" not in got:
            if unproven_workflows(required, runs, jobs):
                return "skipped"
            if "pass" in got:
                return "pass"
            if not required and not [g for g in got if g != "skip"]:
                return "none"
        if waited > 2400:
            return "fail" if (required or "pending" in got) else "none"
        prev = got
        time.sleep(30)


def close_stale_auto_prs(repo):
    rc, so, _ = run(["gh", "pr", "list", "-R", repo, "--state", "open", "--json", "number,headRefName"], 60)
    for p in json.loads(so or "[]") if rc == 0 else []:
        if p["headRefName"].startswith("security/auto-"):
            run(["gh", "pr", "close", str(p["number"]), "-R", repo, "--delete-branch",
                 "--comment", "Superseded by a newer patchkeep run."], 60)


def commit_local(trusted, title):
    """Commit whatever the writer changed. Nothing leaves this machine. Returns the commit sha."""
    if git(trusted, "status", "--porcelain").strip():
        git(trusted, "add", "-A")
        git(trusted, "-c", "user.name=" + CFG["fix"]["git_name"], "-c", "user.email=" + CFG["fix"]["git_email"], "commit", "-q",
            "-m", title)
    return git(trusted, "rev-parse", "HEAD").strip()


def push_branch(trusted, branch):
    git(trusted, "push", "-q", "-u", "origin", branch, timeout=600)


def merge_pinned(repo, pr, sha):
    """Squash-merge exactly `sha`. Returns None on success or a reason string."""
    rc, so, se = run(["gh", "pr", "merge", str(pr), "-R", repo, "--squash", "--delete-branch",
                      "--match-head-commit", sha], 300)
    if rc != 0:
        return "merge failed: " + se.strip()[-120:]
    for _ in range(20):
        if json.loads(must(["gh", "pr", "view", str(pr), "-R", repo, "--json", "state"], 60))["state"] == "MERGED":
            return None
        if killed("DISABLE_AUTOMERGE") or killed("DISABLE_AUTOFIX"):
            break
        time.sleep(30)
    run(["gh", "pr", "merge", str(pr), "-R", repo, "--disable-auto"], 60)
    return "merge was queued and has been cancelled"


def merge_commit(repo, pr):
    return json.loads(must(["gh", "pr", "view", str(pr), "-R", repo, "--json", "mergeCommit"], 60))["mergeCommit"]["oid"]


def revert_if_main_breaks(repo, pr, trusted, base, short, url):
    """After a merge, watch the workflows on the merge commit. If any fails, open a revert PR,
    have it reviewed, and merge it. Returns extra notification text, or ''."""
    msha = merge_commit(repo, pr)
    if not has_workflows(trusted):
        return ""
    state = checks_state(repo, msha, set(), settle=240)
    if state in ("pass", "none"):
        return ""
    if state == "error":
        return " Couldn't read the checks on main after merging; please glance at it."
    if killed("DISABLE_AUTOFIX") or killed("DISABLE_AUTOMERGE"):
        return " It broke checks on main and auto-merge is switched off, so it was not reverted."
    git(trusted, "fetch", "-q", "origin", base, timeout=600)
    rbranch = "security/revert-%s-%d" % (datetime.date.today().isoformat(), os.getpid())
    git(trusted, "checkout", "-q", "-B", rbranch, "origin/" + base)
    git(trusted, "-c", "user.name=" + CFG["fix"]["git_name"], "-c", "user.email=" + CFG["fix"]["git_email"], "revert", "--no-edit", msha)
    git(trusted, "push", "-q", "-u", "origin", rbranch, timeout=600)
    rsha = git(trusted, "rev-parse", "HEAD").strip()
    body = ("## Why\nThe security fix in %s broke checks on %s after merging, so this restores the previous "
            "state. patchkeep will retry the fix.\n\nAutomated by patchkeep." % (url, base))
    rurl = must(["gh", "pr", "create", "-R", repo, "--base", base, "--head", rbranch,
                 "--title", "Revert security fix that broke %s" % base, "--body", body], 120, trusted).strip()
    rpr = int(rurl.rstrip("/").rsplit("/", 1)[-1])
    agree, _ = sol_review(body, raw_diff(trusted, "origin/%s...HEAD" % base), "")
    if not agree:
        return " It broke checks on main. Revert is ready but the reviewer didn't agree: %s" % rurl
    if checks_state(repo, rsha, pr_workflows(trusted)) in ("fail", "error", "skipped"):
        return " It broke checks on main. Revert PR %s failed its own checks, so it's not merged." % rurl
    if killed("DISABLE_AUTOFIX") or killed("DISABLE_AUTOMERGE"):
        return " It broke checks on main. Revert PR is ready but auto-merge is switched off: %s" % rurl
    why = merge_pinned(repo, rpr, rsha)
    return " It broke checks on main, so it was reverted: %s" % rurl if not why else \
        " It broke checks on main. Revert PR %s not merged (%s)." % (rurl, why)


def pkg_list(fixed):
    names = []
    for item in fixed or []:
        name = str(item).split()[0] if str(item).strip() else ""
        if name and name not in names:
            names.append(name)
    return ", ".join(names[:6]) + (" +%d more" % (len(names) - 6) if len(names) > 6 else "")


# ---------------------------------------------------------------- the merge gate

# What may change in a manifest without CI: only entries naming a dependency. Everything else in these
# files (scripts, build backends, sources, registries) can run code, and a lockfile edit proves nothing
# about it.
NPM_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
                    "overrides", "resolutions")
REGISTRY_SPEC = re.compile(r"(npm:(@[\w.-]+/)?[\w.-]+@)?[\w.^~<>=|* +-]*")
# npm reads a spec that starts with "." or ends in a tarball name as a local path, whatever its characters.
# Its own pattern has an unescaped dot in "tar.gz" and ignores trailing whitespace; this is at least as wide.
LOCAL_SPEC = re.compile(r"^\s*\.|[.](tgz|tar.gz|tar)\s*\Z|[.](tgz|tar)", re.I)
OVERRIDE_REF = re.compile(r"\$(@[\w.-]+/)?[\w.-]+")
PYPROJECT_DEP_TABLES = [("project", "dependencies"), ("project", "optional-dependencies"), ("dependency-groups",),
                        ("tool", "poetry", "dependencies"), ("tool", "poetry", "dev-dependencies"),
                        ("tool", "poetry", "group", "*", "dependencies"),
                        ("tool", "uv", "constraint-dependencies"), ("tool", "uv", "override-dependencies")]
POETRY_ENTRY_KEYS = {"version", "extras", "markers", "python", "optional"}
GO_DIRECTIVES = {"module", "go", "toolchain", "godebug", "require", "exclude", "replace", "retract", "tool"}
PIP_OPTION = re.compile(r"(?:^|\s)-")
CODING_DECLARATION = re.compile(r"coding[:=]")


def same(a, b):
    """Equal as the same data of the same types. Python's == takes False for 0 and True for 1, which
    npm and pip do not: `"gypfile": 0` turns on a node-gyp build that `false` turns off."""
    return canonical_json(a) == canonical_json(b)


def canonical_json(value):
    """JSON in which every value carries its type, so two different values (a date and a string that reads
    like one, false and 0) never come out the same."""
    return json.dumps(typed(value), sort_keys=True)


def typed(value):
    if isinstance(value, dict):
        return {"dict": {repr(k): typed(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {"list": [typed(v) for v in value]}
    return {type(value).__name__: repr(value)}


def registry_specs_only(old, new):
    """True when every string value added or changed in the dependency map `new` (against `old`, nested
    maps included) is a registry version spec or a `$name` reference, never a URL, path or git source."""
    if not isinstance(new, dict):
        return False
    old = old if isinstance(old, dict) else {}
    for key, val in new.items():
        if key in old and same(old[key], val):
            continue
        if isinstance(val, dict):
            ok = registry_specs_only(old.get(key), val)
        else:
            ok = isinstance(val, str) and bool(REGISTRY_SPEC.fullmatch(val) or OVERRIDE_REF.fullmatch(val)) \
                and not LOCAL_SPEC.search(val)
        if not ok:
            return False
    return True


def package_json_ok(old_text, new_text):
    try:
        old, new = json.loads(old_text), json.loads(new_text)
    except ValueError:
        return False
    if not (isinstance(old, dict) and isinstance(new, dict)):
        return False

    def rest(doc):
        doc = {k: v for k, v in doc.items() if k not in NPM_DEP_SECTIONS}
        if isinstance(doc.get("pnpm"), dict):
            doc["pnpm"] = {k: v for k, v in doc["pnpm"].items() if k != "overrides"}
            if not doc["pnpm"]:
                del doc["pnpm"]
        return doc

    def pnpm_overrides(doc):
        return doc["pnpm"].get("overrides") if isinstance(doc.get("pnpm"), dict) else None

    if not same(rest(old), rest(new)):
        return False
    maps = [(old.get(k), new[k]) for k in NPM_DEP_SECTIONS if k in new]
    if pnpm_overrides(new) is not None:
        maps.append((pnpm_overrides(old), pnpm_overrides(new)))
    return all(registry_specs_only(o, n) for o, n in maps)


def take_toml(doc, path):
    """Remove the entries at `path` ("*" matches any key) from `doc` and return them as {path: value}.
    A table that held only what was removed goes too, so a new group holding only dependencies leaves
    nothing behind."""
    key, rest = path[0], path[1:]
    out = {}
    if not isinstance(doc, dict):
        return out
    for k in (list(doc) if key == "*" else [key]):
        if k not in doc:
            continue
        if rest:
            got = take_toml(doc[k], rest)
            out.update({(k,) + p: v for p, v in got.items()})
            if got and doc[k] == {}:
                del doc[k]
        else:
            out[(k,)] = doc.pop(k)
    return out


def requirements_ok(old, new):
    """True when every PEP 508 string added in `new` (lists, or tables of lists) names a package by
    registry spec: a `@` or `://` would be a direct URL."""
    if isinstance(new, dict):
        old = old if isinstance(old, dict) else {}
        return all(requirements_ok(old.get(k), v) for k, v in new.items())
    if isinstance(new, list):
        old = old if isinstance(old, list) else []
        return all(isinstance(r, str) and "@" not in r and "://" not in r for r in new if r not in old)
    return False


def poetry_entries_ok(old, new):
    if not isinstance(new, dict):
        return False
    old = old if isinstance(old, dict) else {}
    for name, spec in new.items():
        if name in old and same(old[name], spec):
            continue
        for one in spec if isinstance(spec, list) else [spec]:
            if not (isinstance(one, str) or (isinstance(one, dict) and set(one) <= POETRY_ENTRY_KEYS)):
                return False
    return True


def pyproject_ok(old_text, new_text):
    try:
        old, new = tomllib.loads(old_text), tomllib.loads(new_text)
    except tomllib.TOMLDecodeError:
        return False
    old_deps, new_deps = {}, {}
    for path in PYPROJECT_DEP_TABLES:
        old_deps.update(take_toml(old, path))
        new_deps.update(take_toml(new, path))
    if not same(old, new):
        return False
    return all((poetry_entries_ok if p[:2] == ("tool", "poetry") else requirements_ok)(old_deps.get(p), v)
               for p, v in new_deps.items())


def go_mod_entries(text):
    """[(directive, entry)] for a go.mod, `directive ( ... )` blocks flattened and comments dropped.
    None for anything that isn't plainly written: a quoted or raw string (where a `//` or `)` may sit
    inside the string), a `)` that isn't alone on its line, or a directive name inside a block. Go's own
    parser would read some of those differently, so they need CI."""
    out, block = [], None
    for raw in text.splitlines():
        if '"' in raw or "`" in raw:
            return None
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
                continue
            if ")" in line or "(" in line or line.split(None, 1)[0] in GO_DIRECTIVES:
                return None
            out.append((block, " ".join(line.split())))
            continue
        parts = line.split(None, 1)
        directive, rest = parts[0], (parts[1].strip() if len(parts) > 1 else "")
        if rest == "(":
            block = directive
        elif "(" in rest or ")" in rest:
            return None
        else:
            out.append((directive, " ".join(rest.split())))
    return None if block is not None else out


def go_mod_ok(old_text, new_text):
    """Only `require` lines may change: go.sum pins what they fetch. toolchain, replace and the rest can
    point the build at other code."""
    old, new = go_mod_entries(old_text), go_mod_entries(new_text)
    if old is None or new is None:
        return False
    return sorted(e for e in old if e[0] != "require") == sorted(e for e in new if e[0] != "require")


MANIFEST_CHECKS = {"package.json": package_json_ok, "pyproject.toml": pyproject_ok, "go.mod": go_mod_ok}


def blob_bytes(repo_dir, rev, path):
    """A file's bytes at `rev`, or None when it isn't there. Read from git, never through a link."""
    try:
        return git_bytes(repo_dir, "show", "%s:%s" % (rev, path), timeout=120)
    except RuntimeError:
        return None


def blob(repo_dir, rev, path):
    """A file's text at `rev`, or None when it isn't there or isn't valid UTF-8."""
    data = blob_bytes(repo_dir, rev, path)
    try:
        return None if data is None else data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def plain_requirements(repo_dir, base, path):
    """True when pip reads this requirements file as the same characters this process does: it, and the
    version in the base when there is one, is pure ASCII with no NUL and no coding declaration in the first
    two lines. pip decodes a file by its byte-order mark or a `coding:` line (UTF-16, EBCDIC...) before it
    looks for options, which would hide an `-e` or `--index-url` line from a text check."""
    for rev in ("origin/" + base, "HEAD"):
        data = blob_bytes(repo_dir, rev, path)
        if data is None:
            continue
        text = data.decode("latin-1")
        if not data.isascii() or "\x00" in text or CODING_DECLARATION.search("\n".join(text.split("\n")[:2])):
            return False
    return True


PIP_COMMENT = re.compile(r"(^|\s+)#.*$")
# A --hash option: only where pip starts an option, at a word start, never text inside a file name.
PIP_HASH = re.compile(r"(?:^|(?<=\s))--hash[= ]\S+")
# An option (-e, -r, --index-url, ...) or anything that names a source other than the index: a direct
# reference (`name @ url`), a URL or a path.
PIP_SOURCE = re.compile(r"(?:^|\s)-|@|://|/|\\")
# The only line that names nothing but a package on the index: a PEP 508 name, extras, version
# specifiers and an environment marker. Anything else (`.`, a folder, an archive file name) pip may
# install from disk, running its build hooks.
PIP_SPEC = r"(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*"
PIP_PLAIN = re.compile(r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[A-Za-z0-9._,\s-]*\])?\s*"
                       r"(?:%s(?:,\s*%s)*)?(?:;[A-Za-z0-9_.<>=!~'\"() \t]*)?" % (PIP_SPEC, PIP_SPEC))
ARCHIVE_NAME = re.compile(r"\.(?:zip|whl|tar|tgz|tbz2?|txz|tlz|tar\.gz|tar\.bz2|tar\.xz|tar\.lz|tar\.lzma)$", re.I)


def plain_requirement(line):
    """True for a requirements line that pip can only resolve from the package index. pip reads the
    part before the marker, extras removed, as a local archive whenever it ends like one, version
    specifiers included (`evil==1.0.tar.gz`), so the whole of that part is checked."""
    target = re.sub(r"\[[^\]]*\]$", "", line.split(";", 1)[0].strip()).strip()
    return bool(PIP_PLAIN.fullmatch(line)) and not ARCHIVE_NAME.search(target) and not PIP_SOURCE.search(line)


def pip_logical_lines(text):
    """The requirement lines pip sees: split with str.splitlines() (which breaks at more than git's
    newline), backslash continuations joined the way pip joins them, comments removed, and `--hash` pins
    dropped."""
    out, joined = [], []
    for line in text.splitlines():
        if not line.endswith("\\") or PIP_COMMENT.match(line):
            if PIP_COMMENT.match(line):
                line = " " + line
            out.append("".join(joined + [line]))
            joined = []
        else:
            joined.append(line.strip("\\"))
    if joined:
        out.append("".join(joined))
    return [PIP_HASH.sub(" ", PIP_COMMENT.sub("", l)).strip() for l in out]


def pip_sources_changed(repo_dir, base, path):
    """True when the requirement lines that are pip options or name a source other than the index differ
    between the base and the branch, order included (pip takes the last `--index-url`). Whole logical
    lines are compared, not diff lines: a trailing backslash
    joins the next line, so a changed line can alter an unchanged one. `--hash` pins on their own
    continuation lines are not sources."""
    def risky(rev):
        text = blob(repo_dir, rev, path)
        return None if text is None else [l for l in pip_logical_lines(text) if l and not plain_requirement(l)]
    old, new = risky("origin/" + base), risky("HEAD")
    return new is None or (old or []) != new


# A lockfile may merge without CI only when a real parser reads it and every package in it is a registry
# release or keeps the exact source it had in the base (the project itself, a workspace member). Anything
# else, a local folder or file, a git checkout or a GitHub tarball, runs that code's build or install
# scripts on the next install. Line patterns can be dodged by the other spellings a format allows (a
# quoted TOML key, a JSON escape), so the parser decides, and a lockfile it cannot read needs CI: that is
# yarn.lock, pnpm-lock.yaml, bun.lock and Gemfile.lock, which have no parser in the standard library, and
# mix.lock, which Mix runs as Elixir code. go.sum holds only checksums; go.mod names the sources and has
# its own check.
RELEASE_HOSTS = REGISTRY_HOSTS - {"github.com", "codeload.github.com"}
CRATES_IO = {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
SEMVER = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?")
# What a registry entry of a package lock may hold. npm keeps an entry's fields in its tree, and some
# others, such as `scripts`, it would run on install.
NPM_REGISTRY_KEYS = {"name", "version", "resolved", "integrity", "dev", "optional", "devOptional", "peer",
                     "license", "engines", "bin", "funding", "cpu", "os", "libc", "hasInstallScript",
                     "hasShrinkwrap", "deprecated", "dependencies", "optionalDependencies", "peerDependencies",
                     "peerDependenciesMeta", "bundleDependencies", "requires", "workspaces"}
# The dependency ranges an entry lists (and v1's nested entries, checked on their own). An entry that is
# not a registry release must keep everything else it had in the base.
NPM_RANGE_KEYS = {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
                  "peerDependenciesMeta", "requires"}
UV_FILE_KEYS = {"url", "hash", "size", "upload-time"}


def release_url(url):
    """An https URL on a package registry's own host, not a GitHub checkout or tarball. The host is
    everything up to the first slash, so a user name or a port is never taken for an allowed host."""
    m = re.fullmatch(r"https://([^/@:\s]+)/\S*", url) if isinstance(url, str) else None
    return bool(m) and m.group(1).lower() in RELEASE_HOSTS


def npm_lock(text):
    """{key: [entry]} for every package of a package-lock.json or npm-shrinkwrap.json: the `packages`
    map of lockfile v2 and v3 by path, and the nested `dependencies` tree of v1 (also kept in v2)."""
    doc = json.loads(text)
    packages = doc.get("packages", {}) if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        raise ValueError("not a package lock")
    # How npm reads the file depends on its version and on which of these sections it has.
    out = {("shape", ""): [{"lockfileVersion": doc.get("lockfileVersion"),
                            "sections": [s for s in ("packages", "dependencies") if s in doc]}]}
    out.update((("packages", k), [v]) for k, v in packages.items())
    stack = [("node_modules/", doc.get("dependencies", {}))]
    while stack:
        prefix, deps = stack.pop()
        if not isinstance(deps, dict):
            raise ValueError("not a package lock")
        for name, entry in deps.items():
            out.setdefault(("dependencies", prefix + name), []).append(entry)
            if isinstance(entry, dict) and "dependencies" in entry:
                stack.append((prefix + name + "/node_modules/", entry["dependencies"]))
    # npm resolves each path to a folder, so `./node_modules/x`, `node_modules/x/` or a case or Unicode variant
    # (one folder on macOS) would be a second entry for one folder, and the later one wins. Only one spelling
    # per folder is read.
    seen = set()
    for section, path in out:
        if section == "shape":
            continue
        if path and (posixpath.normpath(path) != path or path.startswith("/") or "\\" in path):
            raise ValueError("a package path npm would rewrite")
        folder = (section, unicodedata.normalize("NFC", path).casefold())
        if folder in seen:
            raise ValueError("two package paths for one folder")
        seen.add(folder)
    return out


def npm_registry(entry):
    return (isinstance(entry, dict) and set(entry) <= NPM_REGISTRY_KEYS and release_url(entry.get("resolved"))
            and isinstance(entry.get("version"), str) and bool(SEMVER.fullmatch(entry["version"])))


def npm_source(entry):
    return {k: v for k, v in entry.items() if k not in NPM_RANGE_KEYS} if isinstance(entry, dict) else entry


# The dependency maps of a lock entry (a v1 entry lists its ranges under `requires`). npm installs what they
# name; only peers may be missing from the lock (lockfiles made with --legacy-peer-deps lack them).
NPM_NEEDS = {"packages": ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"),
             "dependencies": ("requires",)}


def npm_complete(old, new):
    """True when the lock still holds everything npm installs from. No key of the base is gone, the file's
    shape included (it decides how npm reads the file). In a new or changed entry, a dependency spec that
    changed is a registry spec, and every dependency but a peer is where npm looks for it: the entry's own
    node_modules, then each parent's, up to the top."""
    if not set(old) <= set(new):
        return False
    for (section, path), entries in new.items():
        before = old.get((section, path), [])
        prior = before[0] if len(before) == 1 and isinstance(before[0], dict) else {}
        for entry in entries:
            if any(same(entry, b) for b in before):
                continue
            for field in NPM_NEEDS.get(section, ()):
                deps = entry.get(field, {}) if isinstance(entry, dict) else None
                if not isinstance(deps, dict) or not registry_specs_only(prior.get(field), deps):
                    return False
                for dep in ([] if field == "peerDependencies" else deps):
                    at = path
                    while (section, (at + "/" if at else "") + "node_modules/" + dep) not in new:
                        if not at:
                            return False
                        cut = at.rfind("/node_modules/")
                        at = at[:cut] if cut >= 0 else ""
    return not npm_shadowed(old, new)


def npm_folders(path, dep):
    """Every folder Node or npm could find `dep` in for the package at `path`, nearest first: its own
    node_modules, then that of each folder above it."""
    parts = path.split("/") if path else []
    return [("/".join(parts[:i]) + "/" if i else "") + "node_modules/" + dep for i in range(len(parts), -1, -1)]


def npm_shadowed(old, new):
    """True when a dependency whose spec names a source (git, a tarball, a path) would now be found in a
    new folder nearer than where it was found in the base. npm installs the nearer entry, sees that it does
    not satisfy the spec, and fetches the source afresh, so an entry that did not change can still change
    what is installed."""
    fold = lambda key: (key[0], unicodedata.normalize("NFC", key[1]).casefold())
    before, added = {fold(k) for k in old}, {fold(k) for k in new if k not in old}
    if not added:
        return False
    for (section, path), entries in new.items():
        for entry in entries:
            for field in NPM_NEEDS.get(section, ()):
                deps = entry.get(field) if isinstance(entry, dict) else None
                for dep, spec in (deps.items() if isinstance(deps, dict) else ()):
                    if registry_specs_only(None, {dep: spec}):
                        continue
                    for folder in npm_folders(path, dep):
                        if fold((section, folder)) in added:
                            return True
                        if fold((section, folder)) in before:
                            break
    return False


def canon(name):
    """A Python package name the way PyPI compares them."""
    return re.sub(r"[-_.]+", "-", name).lower()


def toml_complete(needs, key=canon, specs=None):
    """The completeness check for a uv.lock, poetry.lock or Cargo.lock: no name has fewer packages than in
    the base, and every dependency of every package is one of its packages, matched by name (as `key`
    compares names in that ecosystem) and, where the lock gives them, by version and source.
    `needs(package)` lists (name, version, source) per dependency. A lock that names dependencies without
    their source also passes `specs(old, new)` over the dependency entries of each new or changed package."""
    def check(old, new):
        if any(len(new.get(name, [])) < len(packages) for name, packages in old.items()):
            return False
        held = {}
        for name, packages in new.items():
            before = old.get(name, [])
            prior = before[0].get("dependencies") if len(before) == 1 else None
            for p in packages:
                held.setdefault(key(p["name"]), []).append(p)
                if specs and not any(same(p, b) for b in before) and not specs(prior, p.get("dependencies", {})):
                    return False
        return all(any((version is None or same(q.get("version"), version))
                       and (source is None or same(q.get("source"), source)) for q in held.get(key(name), []))
                   for packages in new.values() for p in packages for name, version, source in needs(p))
    return check


def uv_needs(p):
    groups = [p.get("dependencies", [])]
    for field in ("optional-dependencies", "dev-dependencies"):
        extra = p.get(field, {})
        if not isinstance(extra, dict):
            raise ValueError(field)
        groups += list(extra.values())
    if not all(isinstance(deps, list) and all(isinstance(d, dict) and isinstance(d.get("name"), str) for d in deps)
               for deps in groups):
        raise ValueError("dependencies")
    return [(d["name"], d.get("version"), d.get("source")) for deps in groups for d in deps]


def poetry_needs(p):
    deps = p.get("dependencies", {})
    if not isinstance(deps, dict):
        raise ValueError("dependencies")
    return [(n, None, None) for n, spec in deps.items() if not (isinstance(spec, dict) and spec.get("optional") is True)]


def cargo_needs(p):
    """Cargo writes a dependency as `name`, adding ` version` and ` (source)` when the name alone is ambiguous."""
    deps = p.get("dependencies", [])
    if not isinstance(deps, list):
        raise ValueError("dependencies")
    out = []
    for d in deps:
        m = re.fullmatch(r"(\S+)(?: (\S+))?(?: \((\S+)\))?", d) if isinstance(d, str) else None
        if not m:
            raise ValueError("dependency")
        out.append(m.groups())
    return out


def toml_packages(text):
    """{name: [package]} for the `[[package]]` tables of a uv.lock, poetry.lock or Cargo.lock."""
    packages = tomllib.loads(text).get("package", [])
    if not isinstance(packages, list) or not all(isinstance(p, dict) and isinstance(p.get("name"), str)
                                                 for p in packages):
        raise ValueError("not a package list")
    out = {}
    for p in packages:
        out.setdefault(p["name"], []).append(p)
    return out


def uv_registry(p):
    source, files = p.get("source"), p.get("wheels", [])
    if not isinstance(files, list):
        return False
    files = files + ([p["sdist"]] if "sdist" in p else [])
    return (isinstance(source, dict) and list(source) == ["registry"] and release_url(source["registry"])
            and all(isinstance(f, dict) and set(f) <= UV_FILE_KEYS and release_url(f.get("url")) for f in files))


LOCK_READERS = {
    "package-lock.json": (npm_lock, npm_registry, npm_source, npm_complete),
    "npm-shrinkwrap.json": (npm_lock, npm_registry, npm_source, npm_complete),
    "uv.lock": (toml_packages, uv_registry, lambda p: [p.get(k) for k in ("source", "sdist", "wheels")],
                toml_complete(uv_needs)),
    # poetry.lock names a dependency without its source, so a changed entry must be a plain version
    # requirement, not a path, URL or git table. Cargo tells `foo-bar` from `foo_bar`.
    "poetry.lock": (toml_packages, lambda p: "source" not in p, lambda p: p.get("source"),
                    toml_complete(poetry_needs, specs=poetry_entries_ok)),
    "Cargo.lock": (toml_packages, lambda p: p.get("source") in CRATES_IO, lambda p: p.get("source"),
                   toml_complete(cargo_needs, key=lambda name: name)),
}


def lock_ok(name, old_text, new_text):
    """True when the lockfile `name` may merge without CI, from its text in the base (None when it is new)
    and on the branch (None when it is deleted). Every package in it is a registry release, or installs from
    the same place as a package under the same key in the base (for uv, its files as well as its source).
    Every package of the base that is not a registry release is still there from that same place: the
    manifest asks for that source, so a registry entry in its stead is not used, and the install fetches
    the source afresh.
    And it still holds everything an install needs (npm_complete, toml_complete): an install resolves anything
    missing afresh, past these checks, the same way it would with the lockfile deleted. Whether a locked
    version is inside the range asked for is left to the release-age rule and the review: that takes each
    tool's own resolver."""
    if name == "go.sum":
        return True
    if name not in LOCK_READERS or new_text is None:
        return False
    read, registry, source, complete = LOCK_READERS[name]
    try:
        old, new = read(old_text) if old_text is not None else {}, read(new_text)
        if not complete(old, new):
            return False
        for key, packages in new.items():
            before = old.get(key, [])
            for p in packages:
                if not registry(p) and not any(same(source(p), source(b)) for b in before):
                    return False
        for key, packages in old.items():
            after = new.get(key, [])
            for b in packages:
                if not registry(b) and not any(same(source(p), source(b)) for p in after):
                    return False
    except (ValueError, TypeError, AttributeError, RecursionError):
        return False
    return True


def dependency_only(repo_dir, base, paths):
    """True when every changed file may merge without PR CI, on the strength of the agent's sandboxed
    before-and-after runs and the review: a lockfile whose packages all still come from a registry release
    (lock_ok; a requirements file without pip options), or a manifest whose only changes are dependency
    entries. Anything else, such as .npmrc, package.json scripts or a build backend, runs code that only
    CI would exercise. `paths` is the local commit's whole file list."""
    for path in paths:
        name = os.path.basename(path)
        if name == "requirements.txt":
            if not plain_requirements(repo_dir, base, path) or pip_sources_changed(repo_dir, base, path):
                return False
            continue
        if name in LOCKFILES:
            if not lock_ok(name, blob(repo_dir, "origin/" + base, path), blob(repo_dir, "HEAD", path)):
                return False
            continue
        if name not in MANIFEST_CHECKS:
            return False
        old, new = blob(repo_dir, "origin/" + base, path), blob(repo_dir, "HEAD", path)
        if old is None or new is None or not MANIFEST_CHECKS[name](old, new):
            return False
    return True


def merge_blockers(checks, dep_only):
    """Why a pushed fix must not merge, in words; [] when it may. The review was settled before the push;
    this is what only the pushed commit can show. `checks` is checks_state(). A required workflow that
    ran but proved nothing ('skipped') counts like having no CI: a change that is only dependency
    entries may merge, anything else may not."""
    reasons = []
    if checks in ("fail", "error"):
        reasons.append("CI %s" % ("failed" if checks == "fail" else "status unknown"))
    if checks == "skipped" and not dep_only:
        reasons.append("its required CI was skipped, so nothing proved the change")
    if checks == "none" and not dep_only:
        reasons.append("it changes code or install-time config and no CI runs on pull requests to prove it")
    if killed("DISABLE_AUTOMERGE") or killed("DISABLE_AUTOFIX"):
        reasons.append("auto-merge is switched off")
    return reasons


def fix(repo, items_path):
    problem = dir_problem()
    if problem:
        raise SystemExit("patchkeep fix: " + problem)
    lock = open(STATE_DIR + "/fix-%s.lock" % slug(repo), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    if killed("DISABLE_AUTOFIX"):
        return
    items = json.load(open(items_path))
    sh = set_hash(items)
    short = repo.split("/", 1)[1]
    # Resolved once: every later path under the work folder is built from this one, and the folder is told
    # apart from a look-alike by its device and inode, not by its name.
    work = os.path.realpath(tempfile.mkdtemp(prefix="patchkeep-%s-" % short, dir=WORK_ROOT))
    # Kept for the whole run: what the trusted side does inside the folder goes through this handle, which
    # a link put at the path later cannot redirect.
    work_fd = os.open(work, OPEN_DIR)
    work_id = work_identity(work_fd)
    os.makedirs(STATE_DIR + "/trusted", exist_ok=True)
    trusted_root = tempfile.mkdtemp(prefix=slug(repo) + "-", dir=STATE_DIR + "/trusted")
    trusted = trusted_root + "/repo"
    agent_name = "repo"
    agent_dir = work + "/" + agent_name
    result_name = "result.json"
    result_file = work + "/" + result_name

    outcome = []

    def result(status, text, **kw):
        outcome.append(dict(kw, repo=repo, status=status, set=sh, items=items_path, text=text))

    def refuse(why, **kw):
        result("blocked", "Fix for %s was not pushed: %s." % (short, why), **kw)

    def copy_ok():
        check_work(work, work_id)
        problems = collect_agent_copy(work_fd, agent_name, holding, trusted)
        if problems:
            refuse("the writer " + "; ".join(p[:140] for p in problems[:3]))
        return not problems

    try:
        must(["gh", "repo", "clone", repo, trusted, "--", "--depth", "200"], 600)
        base = git(trusted, "rev-parse", "--abbrev-ref", "HEAD").strip()
        branch = "security/auto-%s-%d" % (datetime.date.today().isoformat(), os.getpid())
        git(trusted, "checkout", "-q", "-b", branch)
        os.makedirs(agent_dir)
        sync_tree(trusted, agent_dir)
        required_ci = pr_workflows(trusted)
        template = open(os.path.join(HERE, "fix_prompt.md")).read()
        prompt = template.replace("{{REPO}}", repo).replace("{{RESULT_FILE}}", result_file) \
            .replace("{{FINDINGS}}", json.dumps(items, indent=1))
        holding = trusted_root + "/agent-copy"
        res = author(work, work_fd, work_id, agent_dir, prompt, result_name)
        if not copy_ok():
            return
        if res.get("status") != "changes" or not git(trusted, "status", "--porcelain").strip():
            status = res.get("status") if res.get("status") in ("nofix", "failed") else "failed"
            result(status, "Couldn't auto-fix %s: %s" % (short, (res.get("notes") or "no changes made")[:220]), detail=res)
            return

        title = res.get("pr_title") or "security: dependency fixes"
        history, agree, verdict, sha = "", False, "", None
        # Nothing is pushed until every local check and the review have passed on the commit, because CI
        # runs a pushed branch with the repo's secrets.
        for rnd in range(1, REVIEW_ROUNDS + 1):
            if killed("DISABLE_AUTOFIX"):
                refuse("stopped by the kill switch")
                return
            sha = commit_local(trusted, title)
            why = branch_problem(trusted, base)
            if why:
                refuse(why)
                return
            diff, foreign = review_diff(trusted, base)
            if diff is None:
                refuse("it is too large to review in full")
                return
            if foreign:
                refuse("it pulls packages from unexpected hosts (%s)" % ", ".join(foreign[:3]))
                return
            body = (res.get("pr_body") or "") + "\n\nAutomated by patchkeep."
            agree, verdict = sol_review(body, diff, history)
            log("%s review round %d on %s: %s" % (repo, rnd, sha[:10], "AGREE" if agree else "findings"))
            if agree or rnd == REVIEW_ROUNDS:
                break
            res = author(work, work_fd, work_id, agent_dir, prompt + "\n\n## Reviewer findings (round %d)\n\n%s\n\n"
                         "Fix each finding or rebut it with evidence. Then rewrite the result file, with `response` "
                         "listing what you did for each finding." % (rnd, verdict), result_name)
            if not copy_ok():
                return
            history = "Previous review findings:\n%s\n\nAuthor's response:\n%s\n\n" % (verdict, res.get("response", ""))
        if not agree:
            refuse("the reviewer still had findings after %d rounds" % REVIEW_ROUNDS, verdict=verdict[:4000])
            return
        if killed("DISABLE_AUTOFIX"):
            refuse("stopped by the kill switch")
            return

        # Every check passed. Only now does anything leave this machine.
        close_stale_auto_prs(repo)
        push_branch(trusted, branch)
        url = must(["gh", "pr", "create", "-R", repo, "--base", base, "--head", branch,
                    "--title", title, "--body", body], 120, trusted).strip()
        pr = int(url.rstrip("/").rsplit("/", 1)[-1])
        checks = checks_state(repo, sha, required_ci)
        reasons = merge_blockers(checks, checks in ("none", "skipped") and dependency_only(
            trusted, base, changed_paths(trusted, base)))
        if reasons:
            result("blocked", "Fix for %s is ready but not merged (%s): %s" % (short, "; ".join(reasons), url),
                   pr=url, sha=sha, verdict=verdict[:4000])
            return
        why = merge_pinned(repo, pr, sha)
        if why:
            result("blocked", "Fix for %s passed review but wasn't merged (%s): %s" % (short, why, url), pr=url)
            return
        after = revert_if_main_breaks(repo, pr, trusted, base, short, url)
        left = res.get("remaining") or []
        tail = " %d left with no fix yet." % len(left) if left else ""
        result("merged" if not after.startswith(" It broke") else "reverted",
               "Fixed and merged %s: %s.%s %s%s" % (short, pkg_list(res.get("fixed")) or "dependency updates", tail, url, after),
               pr=url, sha=sha, detail=res)
    except WriterRefused as ex:
        refuse("the writer " + str(ex))
    except Exception as ex:
        result("error", "Auto-fix for %s hit an error: %s" % (short, str(ex)[:200]))
    finally:
        os.close(work_fd)
        discard_work(work, trusted_root)
        rmtree_force(trusted_root)
        # Published only after cleanup: done_command may close the window this runs in.
        os.makedirs(RESULTS_DIR, exist_ok=True)
        for res in outcome:
            name = "%s-%s" % (slug(repo), stamp())
            with open(RESULTS_DIR + "/." + name + ".tmp", "w") as f:
                json.dump(res, f, indent=1)
            os.replace(RESULTS_DIR + "/." + name + ".tmp", RESULTS_DIR + "/" + name + ".json")


if __name__ == "__main__":
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if len(sys.argv) >= 2 and sys.argv[1] == "fix":
        fix(sys.argv[2], sys.argv[3])
    else:
        watch(dry="--dry-run" in sys.argv)
