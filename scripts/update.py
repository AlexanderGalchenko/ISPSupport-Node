#!/usr/bin/env python3
"""Fetch and fast-forward the shared node code without touching local settings."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

ORIGIN = "https://github.com/AlexanderGalchenko/ISPSupport-Node.git"
REPO = Path("/ispsupport/node")
STATE = Path("/var/lib/ispsupport-node/update.json")


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    ).stdout.strip()


def save_state(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False) + "\n")
    temporary.chmod(0o640)
    temporary.replace(path)


def update(repo=REPO, state=STATE, origin=ORIGIN):
    result = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        if git(repo, "remote", "get-url", "origin") != origin:
            raise RuntimeError("Unexpected origin; update stopped")
        if git(repo, "status", "--porcelain"):
            raise RuntimeError("Local code changes detected; update stopped")
        if git(repo, "symbolic-ref", "--short", "HEAD") != "main":
            raise RuntimeError("Expected the main branch; update stopped")
        previous = git(repo, "rev-parse", "HEAD")
        result["previous_revision"] = previous
        git(repo, "fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
        target = git(repo, "rev-parse", "refs/remotes/origin/main")
        git(repo, "merge-base", "--is-ancestor", previous, target)
        git(repo, "merge", "--ff-only", "--no-edit", target)
        result.update(status="updated" if target != previous else "unchanged", revision=target)
        save_state(state, result)
        print(json.dumps(result))
        return 0
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        result.update(status="failed", error=detail[-2000:])
        save_state(state, result)
        print(json.dumps(result), file=sys.stderr)
        return 1


if __name__ == "__main__":
    with open("/run/lock/ispsupport-node-update.lock", "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit(0)
        sys.exit(update())
