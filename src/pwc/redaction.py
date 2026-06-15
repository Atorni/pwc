"""Secret redaction. Runs on ALL context before egress to any provider."""
from __future__ import annotations

import re
from dataclasses import dataclass

# Ordered, conservative patterns. Each maps to a stable placeholder.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{30,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        re.DOTALL)),
    ("BEARER", re.compile(r"(?i)\b(?:bearer|authorization:\s*bearer)\s+[A-Za-z0-9._\-]{12,}")),
    ("BASIC_AUTH_URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@")),
    # Generic key=value credential assignments.
    ("ASSIGNED_SECRET", re.compile(
        r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
        r"private[_-]?key|auth)\b\s*[=:]\s*['\"]?([^\s'\"]{4,})")),
    # -p<password> style for DB/auth clients (mysql, psql, etc.). Scoped to those
    # clients so nmap's `-p <ports>` flag is never mistaken for a secret.
    ("INLINE_PW_FLAG", re.compile(
        r"(?i)\b(?:mysql|mysqladmin|mariadb|mysqldump|psql|mongo|mongosh|redis-cli|"
        r"smbclient|mosquitto_(?:pub|sub))\b[^\n]*?\s(-p)(\S{3,})")),
    # Explicit long-form password flags for any tool.
    ("PASSWORD_FLAG", re.compile(r"(?i)(--password[= ])(\S{3,})")),
]


@dataclass
class RedactionResult:
    text: str
    count: int


def redact(text: str) -> RedactionResult:
    if not text:
        return RedactionResult(text=text, count=0)
    count = 0
    out = text
    for label, pattern in _PATTERNS:
        def _sub(m: re.Match[str], _label: str = label) -> str:
            nonlocal count
            count += 1
            # Preserve the key name for assignment-style matches for context.
            if _label == "ASSIGNED_SECRET":
                return f"{m.group(1)}=<REDACTED:{_label}>"
            if _label == "PASSWORD_FLAG":
                return f"{m.group(1)}<REDACTED:PASSWORD>"
            if _label == "INLINE_PW_FLAG":
                # Keep everything up to the password value (client, flags, the -p),
                # redact only the secret itself.
                head = m.group(0)[: m.start(2) - m.start(0)]
                return f"{head}<REDACTED:PASSWORD>"
            return f"<REDACTED:{_label}>"

        out = pattern.sub(_sub, out)
    return RedactionResult(text=out, count=count)


def redact_dict(data: dict) -> tuple[dict, int]:
    total = 0
    cleaned: dict = {}
    for k, v in data.items():
        if isinstance(v, str):
            r = redact(v)
            cleaned[k] = r.text
            total += r.count
        elif isinstance(v, list):
            new_list = []
            for item in v:
                if isinstance(item, str):
                    r = redact(item)
                    new_list.append(r.text)
                    total += r.count
                else:
                    new_list.append(item)
            cleaned[k] = new_list
        elif isinstance(v, dict):
            sub, c = redact_dict(v)
            cleaned[k] = sub
            total += c
        else:
            cleaned[k] = v
    return cleaned, total
