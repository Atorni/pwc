"""Evidence capture. Saves command + output into structured workspace folders."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from pwc.execution import ExecResult

_TAGS = {"recon", "enum", "creds", "vuln", "web", "notes", "finding-evidence"}
_TAG_DIR = {
    "recon": "scans", "enum": "scans", "vuln": "scans", "web": "web",
    "creds": "creds", "notes": "notes", "finding-evidence": "findings",
}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", text.strip())[:60].strip("_")
    return s or "capture"


def save(engagement_dir: Path, result: ExecResult, *, tag: str = "recon",
         target: str | None = None) -> Path:
    if tag not in _TAGS:
        tag = "recon"
    subdir = engagement_dir / _TAG_DIR[tag]
    subdir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    prefix = (target + "_") if target else ""
    base = subdir / f"{prefix}{ts}_{_slug(result.command.split()[0] if result.command else 'cmd')}"

    (base.with_suffix(".out")).write_text(
        f"$ {result.command}\n\n--- STDOUT ---\n{result.stdout}\n"
        f"--- STDERR ---\n{result.stderr}\n", encoding="utf-8")
    meta = {
        "command": result.command, "exit_code": result.exit_code,
        "tag": tag, "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
    }
    (base.with_suffix(".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return base.with_suffix(".out")
