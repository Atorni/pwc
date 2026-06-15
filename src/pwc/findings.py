"""Lightweight findings scratchpad. Drafts only; never fabricates or auto-confirms."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class Finding:
    id: str
    title: str
    target: str = ""
    severity: str = "informational"  # informational|low|medium|high|critical
    status: str = "draft"            # draft|confirmed
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = "TODO: add remediation guidance."
    created: str = ""


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48] or "finding"


def new(findings_dir: Path, title: str, target: str = "",
        severity: str = "informational") -> Finding:
    findings_dir.mkdir(parents=True, exist_ok=True)
    fid = f"{time.strftime('%Y%m%d')}-{_slug(title)}"
    f = Finding(id=fid, title=title, target=target, severity=severity,
                created=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    _write(findings_dir, f)
    return f


def attach(findings_dir: Path, finding_id: str, evidence_path: str) -> Finding:
    f = load(findings_dir, finding_id)
    if evidence_path not in f.evidence:
        f.evidence.append(evidence_path)
    _write(findings_dir, f)
    return f


def load(findings_dir: Path, finding_id: str) -> Finding:
    path = findings_dir / f"{finding_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"finding not found: {finding_id}")
    return Finding(**json.loads(path.read_text("utf-8")))


def list_all(findings_dir: Path) -> list[Finding]:
    if not findings_dir.exists():
        return []
    out = []
    for p in sorted(findings_dir.glob("*.json")):
        try:
            out.append(Finding(**json.loads(p.read_text("utf-8"))))
        except (json.JSONDecodeError, TypeError):
            continue
    return out


def _write(findings_dir: Path, f: Finding) -> None:
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / f"{f.id}.json").write_text(json.dumps(asdict(f), indent=2), encoding="utf-8")
    # Human-readable markdown alongside the JSON.
    md = (f"# {f.title}\n\n- **ID:** {f.id}\n- **Target:** {f.target}\n"
          f"- **Severity:** {f.severity}\n- **Status:** {f.status}\n\n"
          f"## Description\n{f.description or '_(draft)_'}\n\n"
          f"## Evidence\n" + ("\n".join(f"- {e}" for e in f.evidence) or "_none attached_") +
          f"\n\n## Remediation\n{f.remediation}\n")
    (findings_dir / f"{f.id}.md").write_text(md, encoding="utf-8")
