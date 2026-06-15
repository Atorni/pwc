"""`pwc doctor` - config, provider health, shell hook, tmux, permissions."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from pwc import render
from pwc.config import Config, CONFIG_FILE, CACHE_DIR
from pwc.context import CONTEXT_FILE
from pwc.providers import get_provider


def run(cfg: Config) -> int:
    problems = 0
    render.rule("Diagnostics")

    render.kv("config", str(CONFIG_FILE) + (" (exists)" if CONFIG_FILE.exists()
              else " (missing - run `pwc config init`)"))
    if not CONFIG_FILE.exists():
        problems += 1

    # Provider
    try:
        provider = get_provider(cfg.provider, cfg.provider_settings)
        ok, detail = provider.health()
        (render.ok if ok else render.error)(f"provider '{cfg.provider}': {detail}")
        problems += 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - diagnostics must not crash
        render.error(f"provider error: {e}")
        problems += 1

    # Shell hook / context file
    if CONTEXT_FILE.exists():
        render.ok(f"shell context file present: {CONTEXT_FILE}")
    else:
        render.warn("shell context file missing - is the shell hook sourced? "
                    "Run `pwc shell-init` and source it.")
        problems += 1

    # tmux
    render.kv("tmux", "found" if shutil.which("tmux") else "NOT found (optional)")

    # Writable dirs
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        test = CACHE_DIR / ".write_test"
        test.write_text("ok"); test.unlink()
        render.ok(f"cache writable: {CACHE_DIR}")
    except OSError as e:
        render.error(f"cache not writable: {e}")
        problems += 1

    # Common Kali tools (informational only)
    tools = ["nmap", "gobuster", "feroxbuster", "ffuf", "nikto", "smbclient",
             "enum4linux-ng", "sqlmap", "john", "hashcat"]
    present = [t for t in tools if shutil.which(t)]
    render.kv("tools", f"{len(present)}/{len(tools)} found: {', '.join(present) or 'none'}")

    # Privacy posture
    render.kv("privacy", "ON (no shell context sent)" if cfg.privacy_mode else "off")

    render.rule()
    if problems == 0:
        render.ok("No blocking issues found.")
    else:
        render.warn(f"{problems} issue(s) need attention.")
    return 0 if problems == 0 else 1
