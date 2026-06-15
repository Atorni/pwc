from __future__ import annotations

from abc import ABC, abstractmethod


class ProviderError(RuntimeError):
    pass


class Provider(ABC):
    name: str = "base"

    def __init__(self, settings: dict) -> None:
        self.settings = settings or {}

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's raw text response."""

    @abstractmethod
    def health(self) -> tuple[bool, str]:
        """Return (ok, detail) for diagnostics - must not perform a billed call if avoidable."""
