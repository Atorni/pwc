"""Policy engine - allowlist/denylist and confirmation rules."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from pwc.risk import RiskAssessment, DANGEROUS


@dataclass
class PolicyDecision:
    allowed: bool
    blocked_reason: str | None = None
    require_double_confirm: bool = False
    warnings: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.warnings is None:
            self.warnings = []


class PolicyEngine:
    def __init__(self, *, denylist: list[str], allowlist: list[str],
                 confirm_dangerous: bool, double_confirm_dangerous: bool) -> None:
        self.denylist = denylist or []
        self.allowlist = allowlist or []
        self.confirm_dangerous = confirm_dangerous
        self.double_confirm_dangerous = double_confirm_dangerous

    @staticmethod
    def _matches(patterns: list[str], command: str) -> str | None:
        for pat in patterns:
            if fnmatch.fnmatch(command, pat) or pat in command:
                return pat
        return None

    def evaluate(self, command: str, risk: RiskAssessment) -> PolicyDecision:
        deny = self._matches(self.denylist, command)
        if deny:
            return PolicyDecision(allowed=False,
                                  blocked_reason=f"matches denylist pattern: {deny!r}")

        decision = PolicyDecision(allowed=True)

        # If an allowlist is configured, anything outside it gets a warning (not a block),
        # so the tool stays usable while signalling deviation from approved patterns.
        if self.allowlist and not self._matches(self.allowlist, command):
            decision.warnings.append("command is outside the configured allowlist")

        if risk.level == DANGEROUS:
            if self.double_confirm_dangerous or risk.requires_double_confirm:
                decision.require_double_confirm = True

        return decision
