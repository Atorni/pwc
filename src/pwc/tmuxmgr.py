"""tmux session orchestration via subprocess (argv only; no shell injection)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# window name -> purpose
WINDOWS = [
    ("notes", "Notes / AI copilot (run `pwc ask`, `pwc next` here)"),
    ("shell", "General shell operations"),
    ("scans", "Long-running scans (nmap, gobuster, \u2026)"),
    ("web", "Web / HTTP testing"),
    ("logs", "Log watching"),
]


def available() -> bool:
    return shutil.which("tmux") is not None


def _tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["tmux", *args], capture_output=True, text=True)


def session_exists(name: str) -> bool:
    return _tmux("has-session", "-t", name).returncode == 0


def session_name(engagement: str, target: str | None) -> str:
    base = f"pwc-{engagement}"
    return f"{base}-{target}".replace(".", "_") if target else base


def create(engagement: str, target: str | None, workdir: Path) -> str:
    name = session_name(engagement, target)
    if session_exists(name):
        return name
    first, _ = WINDOWS[0]
    _tmux("new-session", "-d", "-s", name, "-n", first, "-c", str(workdir))
    for win, _purpose in WINDOWS[1:]:
        _tmux("new-window", "-t", name, "-n", win, "-c", str(workdir))
    _tmux("select-window", "-t", f"{name}:notes")
    return name


def attach_or_print(name: str) -> None:
    # Cannot attach from inside another program cleanly; print the command.
    import os
    if os.environ.get("TMUX"):
        print(f"  tmux switch-client -t {name}")
    else:
        print(f"  tmux attach -t {name}")


def list_sessions() -> list[str]:
    cp = _tmux("list-sessions", "-F", "#{session_name}")
    if cp.returncode != 0:
        return []
    return [s for s in cp.stdout.splitlines() if s.startswith("pwc-")]
