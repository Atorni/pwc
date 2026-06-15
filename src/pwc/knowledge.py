"""Per-target structured knowledge. Persisted locally; consumed by the next-step engine."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class TargetKnowledge:
    target: str = ""
    hosts: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)   # {port, proto, service, version}
    urls: list[str] = field(default_factory=list)
    shares: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    cred_refs: list[str] = field(default_factory=list)  # references only; never raw secrets
    notes: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    tried_commands: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "TargetKnowledge":
        if path.exists():
            try:
                return cls(**{**asdict(cls()), **json.loads(path.read_text("utf-8"))})
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @staticmethod
    def _add_unique(lst: list, item) -> None:
        if item and item not in lst:
            lst.append(item)


_NMAP_PORT = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.MULTILINE)
_URL = re.compile(r"https?://[^\s'\"<>]+")


def ingest_command_output(k: TargetKnowledge, command: str, output: str) -> int:
    """Parse common tool output and merge structured facts. Returns #facts added."""
    added = 0
    k._add_unique(k.tried_commands, command.strip())

    for m in _NMAP_PORT.finditer(output):
        port, proto, service, version = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
        entry = {"port": int(port), "proto": proto, "service": service, "version": version}
        if entry not in k.ports:
            k.ports.append(entry)
            added += 1

    for u in _URL.findall(output):
        before = len(k.urls)
        k._add_unique(k.urls, u.rstrip(".,);"))
        added += len(k.urls) - before

    # SMB shares from smbclient/smbmap-style listings.
    for m in re.finditer(r"^\s*(\w[\w$.\- ]+?)\s+(?:Disk|READ|WRITE)", output, re.MULTILINE):
        before = len(k.shares)
        k._add_unique(k.shares, m.group(1).strip())
        added += len(k.shares) - before

    return added


def summarize(k: TargetKnowledge) -> str:
    parts = []
    if k.ports:
        ports = ", ".join(f"{p['port']}/{p['proto']} {p['service']}".strip() for p in k.ports)
        parts.append(f"Open services: {ports}")
    if k.urls:
        parts.append(f"URLs: {', '.join(k.urls[:8])}")
    if k.shares:
        parts.append(f"SMB shares: {', '.join(k.shares)}")
    if k.usernames:
        parts.append(f"Usernames: {', '.join(k.usernames)}")
    if k.open_questions:
        parts.append("Open questions: " + "; ".join(k.open_questions[:5]))
    return "\n".join(parts) if parts else "No structured knowledge recorded yet."
