"""Minimal, dependency-free terminal rendering (ANSI)."""
from __future__ import annotations

import os
import sys
from typing import Iterable

_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def _c(code: str) -> str:
    return "" if _NO_COLOR else code


RESET = _c("\033[0m")
BOLD = _c("\033[1m")
DIM = _c("\033[2m")
RED = _c("\033[31m")
GREEN = _c("\033[32m")
YELLOW = _c("\033[33m")
BLUE = _c("\033[34m")
MAGENTA = _c("\033[35m")
CYAN = _c("\033[36m")
GREY = _c("\033[90m")

_RISK_COLORS = {"safe": GREEN, "caution": YELLOW, "dangerous": RED}


def risk_badge(level: str) -> str:
    color = _RISK_COLORS.get(level, YELLOW)
    return f"{color}{BOLD}[{level.upper()}]{RESET}"


def info(msg: str) -> None:
    print(f"{CYAN}\u203a{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}!{RESET} {msg}", file=sys.stderr)


def error(msg: str) -> None:
    print(f"{RED}\u2717{RESET} {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"{GREEN}\u2713{RESET} {msg}")


def rule(title: str = "") -> None:
    bar = "\u2500" * 60
    if title:
        print(f"{GREY}\u2500\u2500 {BOLD}{title}{RESET}{GREY} {'\u2500' * max(0, 56 - len(title))}{RESET}")
    else:
        print(f"{GREY}{bar}{RESET}")


def banner(text: str) -> None:
    print(f"{MAGENTA}{BOLD}\u250c{'\u2500' * (len(text) + 2)}\u2510{RESET}")
    print(f"{MAGENTA}{BOLD}\u2502 {text} \u2502{RESET}")
    print(f"{MAGENTA}{BOLD}\u2514{'\u2500' * (len(text) + 2)}\u2518{RESET}")


def command_block(cmd: str) -> None:
    print(f"  {BOLD}{GREEN}$ {cmd}{RESET}")


def kv(key: str, value: str) -> None:
    print(f"  {BOLD}{key:<12}{RESET}{value}")


def bullets(items: Iterable[str]) -> None:
    for it in items:
        print(f"  {GREY}\u2022{RESET} {it}")
