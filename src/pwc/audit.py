"""Append-only local audit log (JSONL). Never leaves the device."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, record: dict[str, Any]) -> None:
        record["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        record.setdefault("pid", os.getpid())
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def prompt_sent(self, *, action: str, provider: str, redaction_count: int,
                    context_keys: list[str], target: str | None) -> None:
        self._write({
            "event": "prompt_sent", "action": action, "provider": provider,
            "redactions": redaction_count, "context_keys": context_keys, "target": target,
        })

    def suggestion(self, *, action: str, command: str, risk: str,
                   confidence: float, target: str | None) -> None:
        self._write({
            "event": "suggestion", "action": action, "command": command,
            "risk": risk, "confidence": confidence, "target": target,
        })

    def approval(self, *, command: str, approved: bool, risk: str,
                 reason: str | None = None) -> None:
        self._write({
            "event": "approval", "command": command, "approved": approved,
            "risk": risk, "reason": reason,
        })

    def execution(self, *, command: str, exit_code: int,
                  stdout_bytes: int, stderr_bytes: int, target: str | None) -> None:
        self._write({
            "event": "execution", "command": command, "exit_code": exit_code,
            "stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes, "target": target,
        })

    def policy_block(self, *, command: str, rule: str) -> None:
        self._write({"event": "policy_block", "command": command, "rule": rule})

    def read(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
