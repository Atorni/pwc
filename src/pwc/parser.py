"""Parse model output into a structured Suggestion. Robust to extra prose."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class Suggestion:
    command: str = ""
    explanation: str = ""
    model_risk: str = "caution"
    confidence: float = 0.0
    impact: str = ""
    alternatives: list[str] = field(default_factory=list)
    notes: str = ""
    raw: str = ""


def _extract_json(text: str) -> dict | None:
    # Prefer fenced blocks, then the first balanced object.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    break
    if not candidate:
        return None
    try:
        obj = json.loads(candidate)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def parse(text: str) -> Suggestion:
    obj = _extract_json(text) or {}
    risk = str(obj.get("risk", "caution")).lower()
    if risk not in ("safe", "caution", "dangerous"):
        risk = "caution"
    try:
        conf = float(obj.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    alts = obj.get("alternatives") or []
    if not isinstance(alts, list):
        alts = [str(alts)]
    return Suggestion(
        command=str(obj.get("command", "")).strip(),
        explanation=str(obj.get("explanation", "")).strip(),
        model_risk=risk,
        confidence=max(0.0, min(1.0, conf)),
        impact=str(obj.get("impact", "")).strip(),
        alternatives=[str(a) for a in alts][:4],
        notes=str(obj.get("notes", "")).strip(),
        raw=text,
    )
