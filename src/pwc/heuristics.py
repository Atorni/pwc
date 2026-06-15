"""Offline next-step heuristics. Used by the mock provider and as a fallback.

These NEVER auto-run. They only produce suggestions for human review.
"""
from __future__ import annotations

from pwc.knowledge import TargetKnowledge

_SERVICE_NEXT: dict[str, list[str]] = {
    "http": ["whatweb http://{host}",
             "feroxbuster -u http://{host} -w /usr/share/wordlists/dirb/common.txt"],
    "https": ["whatweb https://{host}",
              "feroxbuster -u https://{host} -k -w /usr/share/wordlists/dirb/common.txt"],
    "ssh": ["ssh -o PreferredAuthentications=none {host}  # banner / auth methods only"],
    "smb": ["enum4linux-ng -A {host}", "smbclient -L //{host}/ -N"],
    "microsoft-ds": ["enum4linux-ng -A {host}", "smbclient -L //{host}/ -N"],
    "netbios-ssn": ["enum4linux-ng -A {host}"],
    "ftp": ["nmap -sV -p21 --script ftp-anon {host}"],
    "domain": ["dig any @{host}", "nslookup {host}"],
    "mysql": ["nmap -sV -p3306 --script mysql-info {host}"],
    "ms-sql-s": ["nmap -p1433 --script ms-sql-info {host}"],
    "rdp": ["nmap -p3389 --script rdp-ntlm-info {host}"],
}


def next_steps(k: TargetKnowledge, host_hint: str | None = None) -> list[tuple[str, str]]:
    """Return (command, rationale) pairs based on known services."""
    host = host_hint or (k.hosts[0] if k.hosts else (k.target or "TARGET"))
    out: list[tuple[str, str]] = []

    if not k.ports:
        out.append((f"nmap -sV -sC -p- -T4 {host} -oN scans/{host}_full_tcp.txt",
                    "No ports recorded yet - run a full service/version scan first."))
        return out

    for p in k.ports:
        svc = (p.get("service") or "").lower()
        for key, templates in _SERVICE_NEXT.items():
            if key in svc:
                for t in templates:
                    out.append((t.format(host=host),
                                f"{p['port']}/{p['proto']} looks like {svc}; enumerate it."))
    if not out:
        out.append((f"nmap -sV -sC -p {','.join(str(p['port']) for p in k.ports)} {host}",
                    "Run default scripts against the discovered ports."))
    # De-duplicate while preserving order.
    seen, deduped = set(), []
    for cmd, why in out:
        if cmd not in seen:
            seen.add(cmd)
            deduped.append((cmd, why))
    return deduped[:6]
