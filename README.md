# patchkeep

patchkeep finds vulnerable dependencies in your GitHub repos and fixes them on its own. A sandboxed coding agent makes the fix, a second model reviews it, and it merges once checks pass. No human is in the loop.

This project was called vulnwatch until November 2026. If you ran it under that name, move `~/.config/vulnwatch` to `~/.config/patchkeep` and `~/.local/state/vulnwatch` to `~/.local/state/patchkeep`, change any `vulnwatch` path in your `config.toml` (`state_dir` overrides the new default, so an old value keeps the old folder), rename `VULNWATCH_CONFIG` to `PATCHKEEP_CONFIG` if you set it, and point your cron line at `patchkeep.py`.

Each pass takes a few minutes:

1. **Watch.** It lists every repo you can see that was pushed recently and reads its lockfiles. Then it checks the exact installed versions against [cve.now](https://cve.now), a free merged feed of the CVE List, GitHub advisories, OSV, NVD, EUVD, CISA KEV and EPSS. It also reads GitHub's Dependabot alerts and switches them on for your repos. New repos and new dependencies are picked up on the next pass after a push.
2. **Notify.** It sends one line per repo with new findings, for example `Vulnerable: my-site uses vite 8.2.3 (CVE-2026-112942, high) +5 more. Fixing it now.`
3. **Fix.** A Codex agent works on a plain copy of the repo inside Codex's OS sandbox, with every read and write under `$HOME` denied. It records install, build and test results before its change and again after it.
4. **Review.** Before anything is pushed, a second model (GPT-6.1 Sol by default) reviews the diff of the local commit and the PR description in a fresh session. The author gets up to 3 rounds to fix or rebut its findings. The review must end in `AGREE` on the exact commit that is then pushed.
5. **Push and merge.** Only after the checks and the review pass does it push the branch and open the PR. The merge is pinned to that commit and happens only when all of these hold:
   - the reviewer agreed, and nothing was pushed before that;
   - no lockfile pulls from a git source, a GitHub tarball or a host outside the known registries;
   - every check on the commit passed, including every workflow that runs on pull requests. A required workflow that ran but skipped all its jobs does not count as passing.

   A change may merge without CI (no workflow runs on pull requests, or the required one was skipped) only if every file in the local commit is a lockfile in which every package is still a registry release or keeps the source it already had (`package-lock.json`, `npm-shrinkwrap.json`, `uv.lock`, `poetry.lock` and `Cargo.lock`, read with a real parser; `go.sum`; `requirements.txt` without pip options), or a manifest whose only changes are dependency entries: `package.json` dependency maps and overrides, `pyproject.toml` dependency tables and `go.mod` `require` lines. Scripts, `.npmrc`, build backends, lockfiles it can't parse (`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Gemfile.lock`, `mix.lock`) and any other file need CI to pass. If checks on the default branch fail after a merge, it opens a revert, has it reviewed, and merges the revert.
6. **Report.** It sends one line per outcome, such as `Fixed and merged my-site: vite, devalue. https://github.com/me/my-site/pull/18`.

Its first pass over 71 active repos found 608 vulnerable dependency matches. On one Next.js repo, cve.now matched 15 issues where Dependabot had 11 alerts. In its first end-to-end run, it fixed 4 packages in one repo, the reviewer agreed in the first round, and it merged with no human involved. Where the only fix was a major upgrade it couldn't verify, it reported "couldn't fix" and changed nothing.

## Safety model

The agent that writes the fix is treated as untrusted. Repo files, package metadata and advisory text can all contain prompt injection.

- **No credentials for the agent.** It runs under a Codex permission profile that denies `$HOME`, so it can't read `~/.config/gh`, `~/.git-credentials`, SSH keys, the kill switches or this script. Its network reaches public hosts through Codex's own proxy, so package managers work, and nothing local: no localhost, private address or Unix socket. A local socket, such as a terminal multiplexer's or your service manager's, would let a command start a program outside the sandbox. Its working copy has no `.git` folder.
- **A trusted side does the git work.** This script clones the repo into `state_dir`, where the sandbox can't reach. It moves the agent's copy there before reading it, copies it once more into a private snapshot, and checks the snapshot before anything reaches the checkout. The run stops, with nothing pushed, if the copy holds git metadata in any spelling (`.GIT`, a `.git` file, names that fold to `.git`), a changed `.gitattributes`, `.gitmodules` or `.lfsconfig`, or a symbolic link the repo didn't already have. Then it mirrors the files over without `.git` and commits with hooks off.
- **Nothing is pushed before the checks.** CI runs a pushed branch with the repo's secrets, so the local commit is checked first: no file name that git has to quote, no symbolic links, no change under `.github/`, no lockfile source but a registry release (a git source, a GitHub tarball or any other host counts, read the way the tool reads the file: JSON and TOML escapes decoded, pip's joined lines, and in the formats read line by line no escapes or YAML tags; a `mix.lock` line must be plain data, since Mix runs that file as Elixir), a diff small enough to review, and the reviewer's `AGREE`. Only then does it push, open the PR, and merge with `--match-head-commit`.
- **The reviewer sees the real diff.** The reviewer runs in an empty folder in read-only mode, on a diff taken from the trusted checkout with `--text --no-textconv --no-ext-diff`, so a `.gitattributes` rule (`-diff`, `binary`, a diff driver) can't hide a change. Diffs are read as bytes and split on `\n` only. Very large lockfile diffs drop only unchanged context and integrity hashes. Every changed package line stays.
- **No path the writer controls is trusted.** The work folder is opened once as a handle, and the trusted side creates folders, removes the old result file and reads the new one through that handle (regular files only, links and named pipes are refused). If the folder is swapped for a link or another folder, the run stops. Cleanup moves the work folder under `state_dir` first, then deletes it entry by entry without following links. The writer's Codex profile makes `/tmp` read-only, because the reviewer's verdict file lives there, and gives the writer its own `TMPDIR` inside the work folder. Each writer round runs in its own session, and whatever it left running is killed when the round ends, including a process that started a session of its own: on Linux the fixer adopts every process the round leaves, and on macOS it finds them by their sandbox.
- **CI on the exact commit.** Checks are read from the commit's check runs, statuses and Actions runs, not from the PR.
- **Kill switches.** `touch <state_dir>/DISABLE_AUTOFIX` switches to alert-only, and running fixers stop before their next push or merge. `touch <state_dir>/DISABLE_AUTOMERGE` keeps opening PRs but never merges.

Known limits:

- In repos whose CI runs only on pushes to the default branch, a fix that changes only dependency entries and lockfiles merges on the agent's sandboxed before-and-after results plus the review. The post-merge revert is the backstop.
- A fix that needs a change under `.github/` is refused before the push.
- Browser tests (Playwright, Chromium) can't launch inside the Codex sandbox on macOS. Fixes in those repos tend to end as "couldn't fix" rather than merge.
- Forks are skipped by default because their dependencies usually track upstream.
- cve.now keeps each uploaded lockfile's package names and versions so it can serve that repo's feed. The lockfile file itself is deleted after parsing.

## Requirements

- Python 3.11 or newer, `git`, `rsync`
- [GitHub CLI](https://cli.github.com) signed in with `repo` scope (`gh auth login`)
- [Codex CLI](https://github.com/openai/codex) signed in, with a version that supports permission profiles (`default_permissions`)
- The package managers your repos use (npm, pnpm, yarn, bun, uv, pip, cargo, go, bundler)
- macOS, or Linux with Codex's sandbox available

## Setup

```sh
git clone https://github.com/hunterbohm/patchkeep ~/patchkeep
mkdir -p ~/.config/patchkeep
cp ~/patchkeep/config.example.toml ~/.config/patchkeep/config.toml
# set github.owners, and notify.command if you want texts or Slack messages
python3 ~/patchkeep/patchkeep.py --dry-run
```

The dry run lists every finding and every fixer it would start. It changes nothing.

Then run it every 5 minutes. With cron:

```cron
*/5 * * * * /usr/bin/env python3 $HOME/patchkeep/patchkeep.py >> $HOME/.local/state/patchkeep/notify.log 2>&1
```

The first pass records what already exists without notifying you, then starts fixers for repos that have findings, 2 at a time. After that, you hear only about new findings and outcomes.

## Watching the fixes

By default each fixer runs in the background and logs to `<state_dir>/logs/`. To watch fixes instead, set `fix.launch_command`, for example one tmux window per fix:

```toml
[fix]
launch_command = "tmux new-window -d -n fix-{name} {fix_cmd} && echo fix-{name}"
done_command = "tmux kill-window -t {handle} 2>/dev/null || true"
```

The same hooks work for an agent app that can start threads from the command line. The thread runs `{fix_cmd}`, and `done_command` closes it when the fix merges.

## Machines

patchkeep covers code. For servers and laptops, set `hosts.on_kev_command` to your own patch script. It runs whenever CISA adds an actively exploited vulnerability, and the new ids are in `$PATCHKEEP_NEW_KEV`.

## Tests

```sh
python3 -m unittest discover -s tests
```

## License

MIT
