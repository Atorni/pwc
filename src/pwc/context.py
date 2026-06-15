"""Context collector. Reads metadata written by the shell hook; adds git/venv."""
from __future__ import annotations

import json
import os
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


CONTEXT_FILE = Path(os.environ.get("PWC_CONTEXT_FILE",
                    str(Path.home() / ".cache" / "pwc" / "context.json")))


@dataclass
class ShellContext:
    cwd: str = ""
    shell: str = ""
    user: str = ""
    hostname: str = ""
    last_command: str = ""
    exit_code: int | None = None
    recent_history: list[str] = field(default_factory=list)
    git_branch: str | None = None
    git_repo: str | None = None
    virtualenv: str | None = None
    stderr_snippet: str = ""

    def to_dict(self, *, include_history: bool, history_limit: int) -> dict:
        d = {
            "cwd": self.cwd, "shell": self.shell, "user": self.user,
            "hostname": self.hostname, "last_command": self.last_command,
            "exit_code": self.exit_code, "git_branch": self.git_branch,
            "git_repo": self.git_repo, "virtualenv": self.virtualenv,
            "stderr_snippet": self.stderr_snippet,
        }
        if include_history:
            d["recent_history"] = self.recent_history[-history_limit:]
        return {k: v for k, v in d.items() if v not in (None, "", [])}


def _git_info(cwd: str) -> tuple[str | None, str | None]:
    try:
        top = subprocess.run(["git", "-C", cwd, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=2)
        if top.returncode != 0:
            return None, None
        repo = Path(top.stdout.strip()).name
        branch = subprocess.run(["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
                                capture_output=True, text=True, timeout=2)
        return repo, (branch.stdout.strip() or None)
    except (OSError, subprocess.SubprocessError):
        return None, None


def collect(*, history_limit: int = 15) -> ShellContext:
    ctx = ShellContext()
    data: dict = {}
    if CONTEXT_FILE.exists():
        try:
            data = json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}

    ctx.cwd = data.get("cwd") or os.getcwd()
    ctx.shell = data.get("shell") or Path(os.environ.get("SHELL", "")).name
    ctx.user = data.get("user") or os.environ.get("USER", "")
    ctx.hostname = data.get("hostname") or socket.gethostname()
    ctx.last_command = data.get("last_command", "")
    ec = data.get("exit_code")
    ctx.exit_code = int(ec) if isinstance(ec, (int, str)) and str(ec).lstrip("-").isdigit() else None
    hist = data.get("recent_history") or []
    ctx.recent_history = [str(h) for h in hist][-history_limit:]
    ctx.stderr_snippet = data.get("stderr_snippet", "")

    ctx.virtualenv = os.environ.get("VIRTUAL_ENV")
    if ctx.virtualenv:
        ctx.virtualenv = Path(ctx.virtualenv).name
    ctx.git_repo, ctx.git_branch = _git_info(ctx.cwd)
    return ctx
