"""Execution gate. Nothing here runs without explicit human approval."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from pwc import render
from pwc.audit import AuditLog
from pwc.policy import PolicyDecision, PolicyEngine
from pwc.risk import RiskAssessment, assess, DANGEROUS

_CONFIRM_PHRASE = "yes, run it"


@dataclass
class ExecResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    ran: bool


def _prompt(text: str) -> str:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def approve(command: str, risk: RiskAssessment, decision: PolicyDecision,
            audit: AuditLog) -> bool:
    if not decision.allowed:
        render.error(f"Blocked by policy: {decision.blocked_reason}")
        audit.policy_block(command=command, rule=decision.blocked_reason or "")
        return False

    for w in decision.warnings:
        render.warn(w)
    if risk.privileged:
        render.warn("This command requires elevated privileges (sudo).")

    if risk.level == DANGEROUS and (decision.require_double_confirm):
        render.warn("DANGEROUS command. Double confirmation required.")
        resp = _prompt(f"  Type exactly '{_CONFIRM_PHRASE}' to proceed: ")
        approved = resp == _CONFIRM_PHRASE
    else:
        resp = _prompt("  Run this command? [y/N] ").lower()
        approved = resp in ("y", "yes")

    audit.approval(command=command, approved=approved, risk=risk.level)
    if not approved:
        render.info("Skipped. Nothing was executed.")
    return approved


def run(command: str, *, cwd: str | None = None, timeout: int = 900,
        audit: AuditLog | None = None, target: str | None = None) -> ExecResult:
    """Execute an APPROVED command. Uses bash -c because suggestions may contain
    pipes/redirects; this path is only reached after the gate."""
    render.info("Executing\u2026")
    try:
        proc = subprocess.run(
            ["bash", "-c", command],
            cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        result = ExecResult(command, proc.returncode, proc.stdout, proc.stderr, ran=True)
    except subprocess.TimeoutExpired:
        render.error(f"Command timed out after {timeout}s.")
        result = ExecResult(command, 124, "", "timeout", ran=True)
    except OSError as e:
        render.error(f"Failed to execute: {e}")
        result = ExecResult(command, 127, "", str(e), ran=False)

    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        render.warn(result.stderr.rstrip())
    if result.ran:
        (render.ok if result.exit_code == 0 else render.error)(
            f"Exit code: {result.exit_code}")
    if audit:
        audit.execution(command=command, exit_code=result.exit_code,
                        stdout_bytes=len(result.stdout.encode()),
                        stderr_bytes=len(result.stderr.encode()), target=target)
    return result


def gate_and_run(command: str, policy: PolicyEngine, audit: AuditLog,
                 *, cwd: str | None = None, target: str | None = None) -> ExecResult | None:
    risk = assess(command)
    decision = policy.evaluate(command, risk)
    if not approve(command, risk, decision, audit):
        return None
    return run(command, cwd=cwd, audit=audit, target=target)
