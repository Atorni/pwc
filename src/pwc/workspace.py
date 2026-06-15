"""Engagement/target workspace: structured folder tree + local state."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

FOLDERS = ["scope", "notes", "loot", "scans", "web", "creds", "findings",
           "screenshots", "logs", "commands", "reports", "targets"]

_STATE_FILE = Path.home() / ".cache" / "pwc" / "active.json"


@dataclass
class EngagementMeta:
    name: str
    created: str
    scope_notes: str = ""
    authorization: str = ""
    targets: list[str] = field(default_factory=list)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "engagement"


def root_dir(workspace_root: str) -> Path:
    return Path(workspace_root).expanduser()


def engagement_dir(workspace_root: str, name: str) -> Path:
    return root_dir(workspace_root) / slug(name)


def init_engagement(workspace_root: str, name: str, *, scope_notes: str = "",
                    target_type: str = "", authorization: str = "") -> Path:
    d = engagement_dir(workspace_root, name)
    for folder in FOLDERS:
        (d / folder).mkdir(parents=True, exist_ok=True)
    meta = EngagementMeta(name=name, created=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          scope_notes=scope_notes, authorization=authorization)
    (d / "engagement.json").write_text(json.dumps(asdict(meta), indent=2), encoding="utf-8")
    (d / "scope" / "scope.md").write_text(
        f"# Scope - {name}\n\n- Target type: {target_type}\n- Authorization: "
        f"{authorization or 'RECORD WRITTEN AUTHORIZATION HERE'}\n\n## Notes\n{scope_notes}\n",
        encoding="utf-8")
    return d


def add_target(workspace_root: str, name: str, target: str,
               target_type: str = "host") -> Path:
    d = engagement_dir(workspace_root, name)
    if not d.exists():
        raise FileNotFoundError(f"engagement not found: {name}")
    meta = load_meta(d)
    if target not in meta.targets:
        meta.targets.append(target)
        (d / "engagement.json").write_text(json.dumps(asdict(meta), indent=2), encoding="utf-8")
    tdir = d / "targets" / slug(target)
    tdir.mkdir(parents=True, exist_ok=True)
    kfile = tdir / "knowledge.json"
    if not kfile.exists():
        kfile.write_text(json.dumps(
            {"target": target, "type": target_type, "hosts": [target]}, indent=2),
            encoding="utf-8")
    return tdir


def load_meta(engagement_dir_path: Path) -> EngagementMeta:
    data = json.loads((engagement_dir_path / "engagement.json").read_text("utf-8"))
    return EngagementMeta(**data)


def knowledge_path(workspace_root: str, name: str, target: str) -> Path:
    return engagement_dir(workspace_root, name) / "targets" / slug(target) / "knowledge.json"


# --- active engagement/target state (the "current context") ---

def set_active(name: str, target: str | None) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps({"engagement": name, "target": target}), encoding="utf-8")


def get_active() -> tuple[str | None, str | None]:
    if not _STATE_FILE.exists():
        return None, None
    try:
        d = json.loads(_STATE_FILE.read_text("utf-8"))
        return d.get("engagement"), d.get("target")
    except (OSError, json.JSONDecodeError):
        return None, None
