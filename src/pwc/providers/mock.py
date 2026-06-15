"""Offline provider. Heuristic suggestions so the tool works with no network/key.

Doubles as the seam for a future local model. Returns JSON matching the schema.
"""
from __future__ import annotations

import json
import re

from pwc.providers.base import Provider


def _emit(command: str, explanation: str, risk: str = "caution",
          conf: float = 0.45, impact: str = "", alts=None, notes: str = "") -> str:
    return json.dumps({
        "command": command, "explanation": explanation, "risk": risk,
        "confidence": conf, "impact": impact, "alternatives": alts or [],
        "notes": notes or "Offline heuristic - review carefully before running.",
    })


class MockProvider(Provider):
    name = "mock"

    def complete(self, system: str, user: str) -> str:
        u = user.lower()
        if "explain what this command does" in u:
            cmd = _after(user, "Command:")
            return _emit(cmd, f"This runs `{cmd}`. (Offline mode gives only a generic gloss; "
                              "use a configured provider for a detailed explanation.)",
                         risk="safe", conf=0.3)
        if "the previous command failed" in u:
            cmd = _after(user, "Command:")
            return _emit(cmd, "Offline mode can't diagnose the error. Check the flags, paths, "
                              "and that required tools are installed.", risk="safe", conf=0.2)
        if "find all files over" in u or "files larger" in u:
            return _emit("find . -type f -size +500M -exec ls -lh {} +",
                         "Lists files larger than 500MB under the current directory.",
                         risk="safe", conf=0.8)
        if "open ports" in u or "scan" in u:
            host = _grep_host(user)
            return _emit(f"nmap -sV -sC -p- -T4 {host} -oN scans/{host}_full_tcp.txt",
                         "Full TCP service/version scan with default scripts, saved to scans/.",
                         risk="caution", conf=0.6,
                         notes="Authorized targets only.")
        return _emit("", "Offline mode has no heuristic for this request. Configure the "
                         "Anthropic or OpenAI-compatible provider for full assistance.",
                     risk="safe", conf=0.1)

    def health(self) -> tuple[bool, str]:
        return True, "offline heuristic provider (no network)"


def _after(text: str, marker: str) -> str:
    idx = text.find(marker)
    if idx == -1:
        return ""
    return text[idx + len(marker):].splitlines()[0].strip()


def _grep_host(text: str) -> str:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.\-]+\.[a-z]{2,})\b", text)
    return m.group(1) if m else "TARGET"
