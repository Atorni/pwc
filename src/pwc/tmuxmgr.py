"""tmux session orchestration (argv only; never shell=True; no injection).

A pwc workbench is one tmux session per engagement (and per target when one is
active). Each session has purpose-labelled windows, and the key windows are
pre-split into panes so an operator drops straight into a usable layout:

    notes : [ live notes / copilot ] | [ scratch shell ]
    shell : general shell
    scans : [ long-running scan    ] | [ watch / tail   ]
    web   : web / HTTP testing
    logs  : log watching
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# window name -> purpose (order matters; index 0 is the landing window)
WINDOWS: list[tuple[str, str]] = [
    ("notes", "Notes / AI copilot (run `pwc ask`, `pwc next` here)"),
    ("shell", "General shell operations"),
    ("scans", "Long-running scans (nmap, gobuster, \u2026)"),
    ("web", "Web / HTTP testing"),
    ("logs", "Log watching"),
]

# windows that get a second (horizontal) pane
_SPLIT_WINDOWS = {"notes", "scans"}

_PREFIX = "pwc-"


@dataclass
class SessionInfo:
    name: str
    attached: bool = False
    windows: list[str] = field(default_factory=list)


def available() -> bool:
    return shutil.which("tmux") is not None


def _tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["tmux", *args], capture_output=True, text=True)


def _ok(*args: str) -> bool:
    return _tmux(*args).returncode == 0


def session_exists(name: str) -> bool:
    return _ok("has-session", "-t", name)


def session_name(engagement: str, target: str | None) -> str:
    base = f"{_PREFIX}{engagement}"
    return f"{base}-{target}".replace(".", "_") if target else base


def build_create_commands(name: str, workdir: Path) -> list[list[str]]:
    """Return the exact argv vectors `create()` will run. Pure + testable."""
    wd = str(workdir)
    first = WINDOWS[0][0]
    cmds: list[list[str]] = [
        ["new-session", "-d", "-s", name, "-n", first, "-c", wd],
    ]
    for win, purpose in WINDOWS:
        if win != first:
            cmds.append(["new-window", "-t", name, "-n", win, "-c", wd])
        cmds.append(["set-option", "-w", "-t", f"{name}:{win}", "@pwc_purpose", purpose])
        if win in _SPLIT_WINDOWS:
            cmds.append(["split-window", "-h", "-t", f"{name}:{win}", "-c", wd])
            cmds.append(["select-layout", "-t", f"{name}:{win}", "main-vertical"])
            cmds.append(["select-pane", "-t", f"{name}:{win}.0"])
    cmds.append(["select-window", "-t", f"{name}:{first}"])
    return cmds


def create(engagement: str, target: str | None, workdir: Path) -> str:
    """Create the workbench if absent; return the session name (idempotent)."""
    name = session_name(engagement, target)
    if session_exists(name):
        return name
    for argv in build_create_commands(name, workdir):
        _tmux(*argv)
    return name


def inside_tmux() -> bool:
    return bool(os.environ.get("TMUX"))


def attach(name: str, *, auto: bool = True) -> bool:
    """Attach to a session. When `auto` and attaching is safe, replace this
    process with tmux (the natural way to enter a session); otherwise print the
    command to run. Returns True if an exec/switch was performed."""
    if not session_exists(name):
        return False
    if inside_tmux():
        # Can't nest an attach; switch the current client instead.
        if auto and _ok("switch-client", "-t", name):
            return True
        print(f"  tmux switch-client -t {name}")
        return False
    if auto and os.isatty(0) and os.isatty(1):
        os.execvp("tmux", ["tmux", "attach", "-t", name])  # replaces process
    print(f"  tmux attach -t {name}")
    return False


# Backwards-compatible alias used by older call sites.
def attach_or_print(name: str) -> None:
    attach(name, auto=False)


def kill(name: str) -> bool:
    return _ok("kill-session", "-t", name)


def list_sessions() -> list[str]:
    cp = _tmux("list-sessions", "-F", "#{session_name}")
    if cp.returncode != 0:
        return []
    return [s for s in cp.stdout.splitlines() if s.startswith(_PREFIX)]


def session_info(name: str) -> SessionInfo | None:
    if not session_exists(name):
        return None
    attached = _tmux("display-message", "-p", "-t", name, "#{session_attached}")
    wins = _tmux("list-windows", "-t", name, "-F", "#{window_name}")
    return SessionInfo(
        name=name,
        attached=attached.stdout.strip() not in ("", "0"),
        windows=[w for w in wins.stdout.splitlines() if w] if wins.returncode == 0 else [],
    )


def all_session_info() -> list[SessionInfo]:
    out = []
    for s in list_sessions():
        info = session_info(s)
        if info:
            out.append(info)
    return out
