"""LOCAL risk engine - authoritative for gating. Model risk claims are advisory."""
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


# (regex, level, reason, double_confirm)
_RULES: list[tuple[re.Pattern[str], str, str, bool]] = [
    (re.compile(r"\brm\b.*\s-[a-z]*r[a-z]*f|\brm\b.*\s-[a-z]*f[a-z]*r"), DANGEROUS,
     "recursive force delete (rm -rf)", True),
    (re.compile(r"\brm\b\s+(-\S+\s+)*(/|/\*|~|\$HOME|\.)\s*$"), DANGEROUS,
     "delete of root/home/cwd", True),
    (re.compile(r"\bdd\b\s+.*of=/dev/"), DANGEROUS, "dd writing to a device", True),
    (re.compile(r"\bmkfs(\.\w+)?\b"), DANGEROUS, "filesystem creation (mkfs)", True),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b"), DANGEROUS,
     "system power state change", True),
    (re.compile(r":\(\)\s*\{\s*:\|\:&\s*\}\s*;"), DANGEROUS, "fork bomb pattern", True),
    (re.compile(r">\s*/dev/sd[a-z]"), DANGEROUS, "redirect to raw disk", True),
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh"), DANGEROUS,
     "pipe remote content directly into a shell", True),
    (re.compile(r"\bchmod\b\s+(-R\s+)?0?777\b"), CAUTION, "world-writable permissions", False),
    (re.compile(r"\bchmod\b\s+-R\b.*\s(/|/etc|/usr|/var|/boot)\b"), DANGEROUS,
     "recursive chmod on a system path", True),
    (re.compile(r"\bchown\b\s+-R\b.*\s(/|/etc|/usr|/var)\b"), DANGEROUS,
     "recursive chown on a system path", True),
    (re.compile(r">\s*(/etc/|/boot/|/sys/|/proc/)"), DANGEROUS,
     "redirect into a sensitive system path", True),
    (re.compile(r"\b(rm|cp|mv|chmod|chown)\b.*\s/\S*\*"), CAUTION,
     "wildcard operation on a broad path", False),
    (re.compile(r"\bgit\b.*\b(reset\s+--hard|clean\s+-[a-z]*f|push\s+--force)"), CAUTION,
     "destructive git operation", False),
    (re.compile(r"\bkill(all)?\b\s+-9\b"), CAUTION, "forced process kill", False),
    (re.compile(r"\biptables\b|\bnft\b|\bufw\b"), CAUTION, "firewall change", False),
    (re.compile(r"\btruncate\b|\bshred\b"), DANGEROUS, "data destruction tool", True),
]

# Security tools that need an explicit authorized-use reminder.
_SECURITY_TOOLS = re.compile(
    r"\b(nmap|masscan|gobuster|feroxbuster|ffuf|dirb|nikto|sqlmap|hydra|medusa|"
    r"john|hashcat|crackmapexec|netexec|nxc|enum4linux(?:-ng)?|smbclient|smbmap|"
    r"responder|metasploit|msfconsole|msfvenom|wpscan|tcpdump|aircrack-ng|"
    r"bettercap|impacket-\w+|evil-winrm)\b")

_PRIV_ESC = re.compile(r"\b(sudo|doas)\b")


def assess(command: str) -> RiskAssessment:
    ra = RiskAssessment()
    cmd = command.strip()
    if not cmd:
        return ra

    for pattern, level, reason, double in _RULES:
        if pattern.search(cmd):
            ra.escalate(level, reason, double=double)

    if _PRIV_ESC.search(cmd):
        ra.privileged = True
        # sudo + an already-dangerous op is the worst case.
        if ra.level == DANGEROUS:
            ra.requires_double_confirm = True
            ra.escalate(DANGEROUS, "destructive command run with elevated privileges", double=True)
        else:
            ra.escalate(CAUTION, "requires elevated privileges (sudo)", double=False)

    if _SECURITY_TOOLS.search(cmd):
        ra.escalate(CAUTION, "active security tool - authorized targets only", double=False)

    # Output redirection to user-owned files is fine; flag append/overwrite of dotfiles.
    if re.search(r">\s*~?/?\.(bash|zsh|profile|ssh/)", cmd):
        ra.escalate(CAUTION, "writes to a shell/ssh config file", double=False)

    return ra


def tokenize_safe(command: str) -> list[str] | None:
    """Return argv if the command is a single program with no shell metachars."""
    if re.search(r"[|&;><`$(){}]|\|\||&&", command):
        return None
    try:
        return shlex.split(command)
    except ValueError:
        return None
