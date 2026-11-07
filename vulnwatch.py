#!/usr/bin/env python3
"""vulnwatch: find vulnerable dependencies in your GitHub repos, fix them with a sandboxed
agent, get a second model to review the fix, and merge it. No human in the loop.

  vulnwatch.py                       one watch pass (inventory, match, launch fixers, report)
  vulnwatch.py --dry-run             one pass that prints what it would do; changes nothing
  vulnwatch.py fix OWNER/REPO ITEMS  fixer for one repo (started by the watch pass)

Run the watch pass every few minutes (cron, launchd, systemd). Its stdout is the
notification text; empty stdout means nothing new. See README.md.

Trust split: the fixer agent edits a plain copy of the repo inside an OS sandbox that denies
every read and write under $HOME, so it never sees GitHub or git credentials. This script
commits, pushes, opens the PR, runs the reviewer, and merges only the exact commit it pushed.

Kill switches in the state dir (default ~/.local/state/vulnwatch):
  DISABLE_AUTOFIX    detect and notify only (also stops running fixers before push/merge)
  DISABLE_AUTOMERGE  fix and open PRs, never merge
"""
import base64
import fnmatch
import datetime
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("VULNWATCH_CONFIG", HOME + "/.config/vulnwatch/config.toml")

DEFAULTS = {
    "state_dir": "~/.local/state/vulnwatch",
    "work_root": "/tmp",
    "path": "/opt/homebrew/bin:/usr/local/bin:~/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "github": {"owners": [], "active_days": 120, "ignore": [], "include_forks": False},
    "fix": {
        "enabled": True, "automerge": True, "max_parallel": 2,
        "author_model": "gpt-6-astra", "author_effort": "high",
        "reviewer_model": "gpt-6.1-sol", "reviewer_effort": "high",
        "review_rounds": 3, "timeout_hours": 2,
        "git_name": "vulnwatch", "git_email": "vulnwatch@users.noreply.github.com",
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
DEP_FILES = LOCKFILES | {
    "package.json", "pnpm-workspace.yaml", ".npmrc", ".yarnrc.yml", "pyproject.toml",
    "requirements.in", "Pipfile", "Pipfile.lock", "go.mod", "Cargo.toml", "Gemfile", "mix.exs",
}


# ---------------------------------------------------------------- helpers

def env(**extra):
    return dict(os.environ, PATH=PATH_ENV, GH_PROMPT_DISABLED="1", **extra)


def run(cmd, timeout=120, cwd=None, stdin=None, environ=None):
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
    req = urllib.request.Request(url, data=data, headers=dict({"User-Agent": "vulnwatch"}, **(headers or {})))
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
    rc, so, _ = run(["pgrep", "-f", "vulnwatch.py fix %s " % repo], 10)
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
    d = tempfile.mkdtemp(prefix="vulnwatch-tree-", dir=WORK_ROOT)
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
                         start_new_session=True, env=env(VULNWATCH_NEW_KEV=",".join(new)))
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
    fix_cmd = " ".join(shlex.quote(a) for a in ["env", "VULNWATCH_CONFIG=" + os.path.abspath(CONFIG_PATH),
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
            texts.append("vulnwatch is not fixing anything: " + problem)
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
        texts.append("vulnwatch has had errors for an hour: %s" % errors[0][:160])

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


def is_dep_file(path):
    return os.path.basename(path) in DEP_FILES


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


def split_diff(diff):
    sections, cur = [], None
    for line in diff_lines(diff):
        if line.startswith("diff --git"):
            cur = [line.split(" b/", 1)[-1], [line]]
            sections.append(cur)
        elif cur:
            cur[1].append(line)
    return [(path, "\n".join(lines)) for path, lines in sections]


def foreign_sources(diff):
    """Hosts on added lockfile lines that are not well-known package registries."""
    hosts = set()
    for path, text in split_diff(diff):
        if os.path.basename(path) not in LOCKFILES:
            continue
        for line in diff_lines(text):
            if line.startswith("+"):
                hosts |= {h.lower() for h in re.findall(r"https?://([^/\s\"']+)", line)} - REGISTRY_HOSTS
    return sorted(hosts)


def review_diff(repo_dir, base):
    """The branch diff for review, from the trusted checkout. Returns (diff, foreign hosts);
    diff is None if it is too big to review even after reduce_diff."""
    diff = raw_diff(repo_dir, "origin/%s...HEAD" % base)
    return reduce_diff(diff), foreign_sources(diff)


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
    rdir = tempfile.mkdtemp(prefix="vulnwatch-review-", dir=WORK_ROOT)
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


SYNC_EXCLUDES = [".git/", "node_modules/", ".venv/", "venv/", "__pycache__/", ".pnpm-store/", ".next/",
                 ".turbo/", ".cache/", ".parcel-cache/", ".pytest_cache/", ".mypy_cache/", "target/"]


def sync_tree(src, dst):
    """Mirror src's working files onto dst. Never copies or touches .git; symlinks stay links."""
    cmd = ["rsync", "-a", "--delete", "--no-specials", "--no-devices"]
    for e in SYNC_EXCLUDES:
        cmd += ["--exclude", e]
    must(cmd + [src.rstrip("/") + "/", dst.rstrip("/") + "/"], 900)


def collect_agent_copy(agent_dir, holding, trusted):
    """Move the agent's copy under HOME (which the sandbox cannot touch) before reading it, so a
    leftover process cannot swap it for a symlink mid-sync. Then mirror it onto the trusted checkout
    and move it back for the next round."""
    try:
        os.rename(agent_dir, holding)
    except OSError as ex:
        raise RuntimeError("cannot move the agent copy into the state dir (%s). Set work_root to a "
                           "folder outside $HOME on the same filesystem as state_dir." % ex)
    try:
        if os.path.islink(holding) or not os.path.isdir(holding):
            raise RuntimeError("agent copy is not a plain directory; refusing to read it")
        sync_tree(holding, trusted)
    finally:
        os.rename(holding, agent_dir)


def author(work, agent_dir, prompt, result_file):
    """Run the fixer agent in Codex's OS sandbox. It sees a plain copy of the repo with no .git,
    can write only under the work dir in /tmp, and every read or write under the real HOME is
    denied, so GitHub and git credentials and the trusted checkout are unreachable. Network stays
    on for package installs. Returns its result JSON."""
    home = work + "/home"
    os.makedirs(home, exist_ok=True)
    if os.path.exists(result_file):
        os.remove(result_file)
    environ = env(HOME=home, CODEX_HOME=HOME + "/.codex", XDG_CACHE_HOME=home + "/.cache",
                  GIT_CONFIG_GLOBAL="/dev/null", GH_CONFIG_DIR=home + "/gh")
    for k in ("GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK"):
        environ.pop(k, None)
    rc, so, se = run(["codex", "exec", "-m", CFG["fix"]["author_model"], "-c", "model_reasoning_effort=" + CFG["fix"]["author_effort"],
                      "-c", 'default_permissions="vulnfix"',
                      "-c", 'permissions.vulnfix.extends=":workspace"',
                      "-c", 'permissions.vulnfix.filesystem={"%s"="deny"}' % HOME,
                      "-c", "permissions.vulnfix.network.enabled=true",
                      "--add-dir", work, "--skip-git-repo-check", "-C", agent_dir, "-"],
                     FIX_TIMEOUT, cwd=agent_dir, stdin=prompt, environ=environ)
    print(so[-20000:], se[-5000:], flush=True)
    try:
        return json.load(open(result_file))
    except (OSError, ValueError):
        raise RuntimeError("fixer agent wrote no result (rc=%s)" % rc)


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


def commit_checks(repo, sha):
    """(outcomes, workflow paths with a run) for every check run, commit status and Actions run
    on exactly `sha`."""
    out, paths = [], set()
    for r in paged("repos/%s/commits/%s/check-runs?per_page=100" % (repo, sha), "check_runs"):
        out.append("pending" if r["status"] != "completed" else
                   "pass" if r["conclusion"] in ("success", "neutral") else
                   "skip" if r["conclusion"] == "skipped" else "fail")
    latest = {}
    for st in gh_json("repos/%s/commits/%s/statuses?per_page=100" % (repo, sha), paginate=True):
        latest.setdefault(st["context"], st["state"])
    for state in latest.values():
        out.append({"success": "pass", "pending": "pending"}.get(state, "fail"))
    for r in paged("repos/%s/actions/runs?head_sha=%s&per_page=100" % (repo, sha), "workflow_runs"):
        paths.add(r.get("path", "").split("@", 1)[0])
        out.append("pending" if r["status"] != "completed" else
                   "pass" if r["conclusion"] in ("success", "neutral") else
                   "skip" if r["conclusion"] == "skipped" else "fail")
    return out, paths


def checks_state(repo, sha, required, settle=180):
    """'pass', 'none', 'fail' or 'error' for everything reported on exactly `sha`.
    `required` is the set of workflow paths that must each have a run. Waits at least `settle`
    seconds and for two identical polls. 'none' only when nothing is required and nothing ran."""
    start, prev = now(), None
    while True:
        try:
            got, paths = commit_checks(repo, sha)
            got = sorted(got)
        except Exception:
            return "error"
        if "fail" in got:
            return "fail"
        waited = now() - start
        settled = waited >= settle and got == prev and required <= paths
        if settled and "pass" in got and "pending" not in got:
            return "pass"
        if settled and not required and not [g for g in got if g != "skip"]:
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
                 "--comment", "Superseded by a newer vulnwatch run."], 60)


def commit_and_push(trusted, branch, title):
    if git(trusted, "status", "--porcelain").strip():
        git(trusted, "add", "-A")
        git(trusted, "-c", "user.name=" + CFG["fix"]["git_name"], "-c", "user.email=" + CFG["fix"]["git_email"], "commit", "-q",
            "-m", title)
    git(trusted, "push", "-q", "-u", "origin", branch, timeout=600)
    return git(trusted, "rev-parse", "HEAD").strip()


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
            "state. vulnwatch will retry the fix.\n\nAutomated by vulnwatch." % (url, base))
    rurl = must(["gh", "pr", "create", "-R", repo, "--base", base, "--head", rbranch,
                 "--title", "Revert security fix that broke %s" % base, "--body", body], 120, trusted).strip()
    rpr = int(rurl.rstrip("/").rsplit("/", 1)[-1])
    agree, _ = sol_review(body, raw_diff(trusted, "origin/%s...HEAD" % base), "")
    if not agree:
        return " It broke checks on main. Revert is ready but the reviewer didn't agree: %s" % rurl
    if checks_state(repo, rsha, pr_workflows(trusted)) in ("fail", "error"):
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


def fix(repo, items_path):
    problem = dir_problem()
    if problem:
        raise SystemExit("vulnwatch fix: " + problem)
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
    work = tempfile.mkdtemp(prefix="vulnwatch-%s-" % short, dir=WORK_ROOT)
    os.makedirs(STATE_DIR + "/trusted", exist_ok=True)
    trusted_root = tempfile.mkdtemp(prefix=slug(repo) + "-", dir=STATE_DIR + "/trusted")
    trusted = trusted_root + "/repo"
    agent_dir = work + "/repo"
    result_file = work + "/result.json"

    outcome = []

    def result(status, text, **kw):
        outcome.append(dict(kw, repo=repo, status=status, set=sh, items=items_path, text=text))

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
        res = author(work, agent_dir, prompt, result_file)
        collect_agent_copy(agent_dir, holding, trusted)
        if res.get("status") != "changes" or not git(trusted, "status", "--porcelain").strip():
            status = res.get("status") if res.get("status") in ("nofix", "failed") else "failed"
            result(status, "Couldn't auto-fix %s: %s" % (short, (res.get("notes") or "no changes made")[:220]), detail=res)
            return

        close_stale_auto_prs(repo)
        pr, url, history, agree, verdict, sha = None, None, "", False, "", None
        for rnd in range(1, REVIEW_ROUNDS + 1):
            if killed("DISABLE_AUTOFIX"):
                result("blocked", "Auto-fix for %s stopped by the kill switch." % short, pr=url)
                return
            sha = commit_and_push(trusted, branch, res.get("pr_title") or "security: dependency fixes")
            body = (res.get("pr_body") or "") + "\n\nAutomated by vulnwatch."
            if pr is None:
                url = must(["gh", "pr", "create", "-R", repo, "--base", base, "--head", branch,
                            "--title", res.get("pr_title") or "security: dependency fixes", "--body", body], 120, trusted).strip()
                pr = int(url.rstrip("/").rsplit("/", 1)[-1])
            else:
                run(["gh", "pr", "edit", str(pr), "-R", repo, "--body", body], 60)
            diff, foreign = review_diff(trusted, base)
            if diff is None:
                result("blocked", "Fix for %s is too large to review in full, so it's not merged: %s" % (short, url), pr=url)
                return
            if foreign:
                result("blocked", "Fix for %s pulls packages from unexpected hosts (%s), so it's not merged: %s" % (
                    short, ", ".join(foreign[:3]), url), pr=url)
                return
            agree, verdict = sol_review(body, diff, history)
            log("%s review round %d on %s: %s" % (repo, rnd, sha[:10], "AGREE" if agree else "findings"))
            if agree or rnd == REVIEW_ROUNDS:
                break
            res = author(work, agent_dir, prompt + "\n\n## Reviewer findings (round %d)\n\n%s\n\n"
                         "Fix each finding or rebut it with evidence. Then rewrite the result file, with `response` "
                         "listing what you did for each finding." % (rnd, verdict), result_file)
            collect_agent_copy(agent_dir, holding, trusted)
            history = "Previous review findings:\n%s\n\nAuthor's response:\n%s\n\n" % (verdict, res.get("response", ""))

        files = json.loads(must(["gh", "pr", "view", str(pr), "-R", repo, "--json", "files"], 60))["files"]
        dep_only = all(is_dep_file(f["path"]) for f in files)
        checks = checks_state(repo, sha, required_ci)
        reasons = []
        if not agree:
            reasons.append("reviewer still had findings after %d rounds" % REVIEW_ROUNDS)
        if checks in ("fail", "error"):
            reasons.append("CI %s" % ("failed" if checks == "fail" else "status unknown"))
        if checks == "none" and not dep_only:
            reasons.append("it changes code and no CI runs on pull requests to prove it")
        if killed("DISABLE_AUTOMERGE") or killed("DISABLE_AUTOFIX"):
            reasons.append("auto-merge is switched off")
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
    except Exception as ex:
        result("error", "Auto-fix for %s hit an error: %s" % (short, str(ex)[:200]))
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(trusted_root, ignore_errors=True)
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
