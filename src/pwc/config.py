"""Config manager. Reads TOML; supplies secure defaults."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("PWC_CONFIG_DIR", str(Path.home() / ".config" / "pwc")))
CONFIG_FILE = CONFIG_DIR / "config.toml"
CACHE_DIR = Path(os.environ.get("PWC_CACHE_DIR", str(Path.home() / ".cache" / "pwc")))
DATA_DIR = Path(os.environ.get("PWC_DATA_DIR", str(Path.home() / ".local" / "share" / "pwc")))


@dataclass
class Config:
    provider: str = "mock"
    provider_settings: dict = field(default_factory=dict)
    workspace_root: str = str(Path.home() / "engagements")
    # privacy / context
    privacy_mode: bool = False
    include_history: bool = True
    history_limit: int = 15
    max_context_chars: int = 6000
    # policy
    confirm_dangerous: bool = True
    double_confirm_dangerous: bool = True
    denylist: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    # paths
    audit_log: str = str(DATA_DIR / "audit.jsonl")

    def effective_history(self) -> bool:
        return self.include_history and not self.privacy_mode


def _defaults_dict() -> dict:
    return {
        "provider": "mock",
        "anthropic": {"model": "claude-sonnet-4-6", "max_tokens": 1024, "timeout": 30},
        "openai_compat": {"base_url": "https://api.openai.com/v1",
                          "model": "gpt-4o-mini", "max_tokens": 1024, "timeout": 30},
        "workspace": {"root": str(Path.home() / "engagements")},
        "privacy": {"privacy_mode": False, "include_history": True,
                    "history_limit": 15, "max_context_chars": 6000},
        "policy": {"confirm_dangerous": True, "double_confirm_dangerous": True,
                   "denylist": [], "allowlist": []},
    }


def load() -> Config:
    raw = _defaults_dict()
    if CONFIG_FILE.exists():
        try:
            user_cfg = tomllib.loads(CONFIG_FILE.read_text("utf-8"))
            _deep_merge(raw, user_cfg)
        except (OSError, tomllib.TOMLDecodeError):
            pass

    provider = raw.get("provider", "mock")
    psettings = raw.get(provider if provider != "openai" else "openai_compat", {})
    privacy = raw.get("privacy", {})
    policy = raw.get("policy", {})

    return Config(
        provider=provider,
        provider_settings=psettings if isinstance(psettings, dict) else {},
        workspace_root=raw.get("workspace", {}).get("root", str(Path.home() / "engagements")),
        privacy_mode=bool(privacy.get("privacy_mode", False)),
        include_history=bool(privacy.get("include_history", True)),
        history_limit=int(privacy.get("history_limit", 15)),
        max_context_chars=int(privacy.get("max_context_chars", 6000)),
        confirm_dangerous=bool(policy.get("confirm_dangerous", True)),
        double_confirm_dangerous=bool(policy.get("double_confirm_dangerous", True)),
        denylist=list(policy.get("denylist", [])),
        allowlist=list(policy.get("allowlist", [])),
    )


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, CACHE_DIR, DATA_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_example(force: bool = False) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists() and not force:
        return CONFIG_FILE
    CONFIG_FILE.write_text(_EXAMPLE_TOML, encoding="utf-8")
    return CONFIG_FILE


_EXAMPLE_TOML = """\
# Pentest Workspace Copilot configuration
# provider: "anthropic" | "openai" | "mock" (offline)
provider = "mock"

[anthropic]
# API key is read from $ANTHROPIC_API_KEY (preferred). Do not store secrets here.
model = "claude-sonnet-4-6"
max_tokens = 1024
timeout = 30

[openai_compat]
base_url = "https://api.openai.com/v1"
model = "gpt-4o-mini"
max_tokens = 1024
timeout = 30

[workspace]
root = "~/engagements"

[privacy]
privacy_mode = false        # true = never send shell context, command-only prompts
include_history = true
history_limit = 15
max_context_chars = 6000

[policy]
confirm_dangerous = true
double_confirm_dangerous = true
denylist = ["rm -rf /*", "mkfs*", ":(){ :|:& };:"]
allowlist = []              # empty = allow with warnings; populate to restrict
"""
