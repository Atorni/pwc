"""LOCAL risk engine - authoritative for gating. Model risk claims are advisory.

Design notes
------------
* The model's self-reported risk is never trusted for gating; `assess()` is.
* Rules are grouped by intent (destructive / filesystem / power-state /
  remote-exec / permissions / security-tool) so they stay readable and easy to
  extend without turning into one giant regex.
* A small normalization pass clusters separated short flags so evasions like
  `rm -r -f x` and `rm --recursive --force x` are caught the same as `rm -rf x`.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

SAFE, CAUTION, DANGEROUS = "safe", "caution", "dangerous"
_ORDER = {SAFE: 0, CAUTION: 1, DANGEROUS: 2}


@dataclass
class RiskAssessment:
    level: str = SAFE
    reasons: list[str] = field(default_factory=list)
    requires_double_confirm: bool = False
    privileged: bool = False

    def escalate(self, level: str, reason: str, *, double: bool = False) -> None:
        if _ORDER[level] > _ORDER[self.level]:
            self.level = level
        if reason not in self.reasons:
            self.reasons.append(reason)
        if double:
            self.requires_double_confirm = True


# --- regex rule groups: (pattern, level, reason, double_confirm) ---
Rule = tuple[re.Pattern[str], str, str, bool]


def _r(pattern: str, level: str, reason: str, double: bool = False) -> Rule:
    return (re.compile(pattern), level, reason, double)


# Destructive data/device operations.
_DESTRUCTIVE: list[Rule] = [
    _r(r"\bdd\b\s+.*\bof=/dev/", DANGEROUS, "dd writing to a device", True),
    _r(r"\bmkfs(\.\w+)?\b", DANGEROUS, "filesystem creation (mkfs)", True),
    _r(r"\bwipefs\b", DANGEROUS, "filesystem signature wipe (wipefs)", True),
    _r(r">\s*/dev/sd[a-z]", DANGEROUS, "redirect to a raw disk device", True),
    _r(r"\b(truncate|shred)\b", DANGEROUS, "data destruction tool", True),
    _r(r":\(\)\s*\{\s*:\|\:&\s*\}\s*;", DANGEROUS, "fork bomb pattern", True),
    _r(r"\bcrontab\b\s+-r\b", DANGEROUS, "removes all cron jobs (crontab -r)", True),
    _r(r"\b(userdel|groupdel)\b", CAUTION, "deletes a user/group account", False),
]

# Filesystem-scope operations on sensitive paths.
_FILESYSTEM: list[Rule] = [
    _r(r"\brm\b\s+(-\S+\s+)*(/|/\*|~|\$HOME|\.)\s*$", DANGEROUS,
       "delete of root/home/cwd", True),
    _r(r"\bchmod\b\s+(-R\s+)?0?777\b", CAUTION, "world-writable permissions", False),
    _r(r"\bchmod\b\s+-R\b.*\s(/|/etc|/usr|/var|/boot)\b", DANGEROUS,
       "recursive chmod on a system path", True),
    _r(r"\bchown\b\s+-R\b.*\s(/|/etc|/usr|/var)\b", DANGEROUS,
       "recursive chown on a system path", True),
    _r(r">\s*(/etc/|/boot/|/sys/|/proc/)", DANGEROUS,
       "redirect into a sensitive system path", True),
    _r(r"\b(rm|cp|mv|chmod|chown)\b.*\s/\S*\*", CAUTION,
       "wildcard operation on a broad path", False),
    _r(r">\s*~?/?\.(bash|zsh|profile|ssh/)", CAUTION,
       "writes to a shell/ssh config file", False),
]

# System power-state changes.
_POWER: list[Rule] = [
    _r(r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b", DANGEROUS,
       "system power state change", True),
]

# Remote code execution / supply-chain footguns.
_REMOTE_EXEC: list[Rule] = [
    _r(r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(ba|z|d)?sh\b", DANGEROUS,
       "pipes remote content directly into a shell", True),
]

# Network / firewall / capture (operationally risky, rarely catastrophic).
_NETWORK: list[Rule] = [
    _r(r"\b(iptables|nft|ufw)\b.*(\s-F\b|--flush|\bflush\b|\breset\b)", DANGEROUS,
       "flushes firewall rules", True),
    _r(r"\b(iptables|nft|ufw)\b", CAUTION, "firewall change", False),
    _r(r"\bkill(all)?\b\s+-9\b", CAUTION, "forced process kill", False),
    _r(r"\bgit\b.*\b(reset\s+--hard|clean\s+-[a-z]*f|push\s+--force)", CAUTION,
       "destructive git operation", False),
]

_RULES: list[Rule] = (_DESTRUCTIVE + _FILESYSTEM + _POWER
                      + _REMOTE_EXEC + _NETWORK)

# Active security tools that need an authorized-use reminder.
_SECURITY_TOOLS = re.compile(
    r"\b(nmap|masscan|gobuster|feroxbuster|ffuf|dirb|nikto|sqlmap|hydra|medusa|"
    r"john|hashcat|crackmapexec|netexec|nxc|enum4linux(?:-ng)?|smbclient|smbmap|"
    r"responder|metasploit|msfconsole|msfvenom|wpscan|tcpdump|aircrack-ng|"
    r"bettercap|impacket-\w+|evil-winrm)\b")

_PRIV_ESC = re.compile(r"\b(sudo|doas)\b")


def _is_rm_recursive_force(cmd: str) -> bool:
    """True if a command is an `rm` that is BOTH recursive AND forced, however
    the flags are spelled (-rf, -fr, -r -f, --recursive --force, bundled, ...)."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    if "rm" not in tokens and not any(t.endswith("/rm") for t in tokens):
        return False
    recursive = force = False
    for tok in tokens:
        if not tok.startswith("-"):
            continue
        if tok in ("--recursive", "-R"):
            recursive = True
        if tok == "--force":
            force = True
        if tok.startswith("-") and not tok.startswith("--"):
            letters = tok[1:]
            if "r" in letters or "R" in letters:
                recursive = True
            if "f" in letters:
                force = True
    return recursive and force


def assess(command: str) -> RiskAssessment:
    ra = RiskAssessment()
    cmd = command.strip()
    if not cmd:
        return ra

    if _is_rm_recursive_force(cmd):
        ra.escalate(DANGEROUS, "recursive force delete (rm -rf)", double=True)

    for pattern, level, reason, double in _RULES:
        if pattern.search(cmd):
            ra.escalate(level, reason, double=double)

    if _PRIV_ESC.search(cmd):
        ra.privileged = True
        if ra.level == DANGEROUS:
            ra.escalate(DANGEROUS, "destructive command run with elevated privileges",
                        double=True)
        else:
            ra.escalate(CAUTION, "requires elevated privileges (sudo)", double=False)

    if _SECURITY_TOOLS.search(cmd):
        ra.escalate(CAUTION, "active security tool - authorized targets only", double=False)

    return ra


def tokenize_safe(command: str) -> list[str] | None:
    """Return argv if the command is a single program with no shell metachars."""
    if re.search(r"[|&;><`$(){}]|\|\||&&", command):
        return None
    try:
        return shlex.split(command)
    except ValueError:
        return None
