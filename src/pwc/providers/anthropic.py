"""Anthropic provider via stdlib urllib (no SDK dependency)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from pwc.providers.base import Provider, ProviderError

_ENDPOINT = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class AnthropicProvider(Provider):
    name = "anthropic"

    def _api_key(self) -> str:
        key = os.environ.get("ANTHROPIC_API_KEY") or self.settings.get("api_key", "")
        if not key:
            raise ProviderError("ANTHROPIC_API_KEY not set")
        return key

    def _model(self) -> str:
        return self.settings.get("model", "claude-sonnet-4-6")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self._model(),
            "max_tokens": int(self.settings.get("max_tokens", 1024)),
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")
        req = urllib.request.Request(_ENDPOINT, data=body, method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("x-api-key", self._api_key())
        req.add_header("anthropic-version", _API_VERSION)
        timeout = float(self.settings.get("timeout", 30))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            raise ProviderError(f"Anthropic HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise ProviderError(f"Anthropic network error: {e}") from e
        chunks = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        text = "".join(chunks).strip()
        if not text:
            raise ProviderError("empty response from Anthropic")
        return text

    def health(self) -> tuple[bool, str]:
        try:
            self._api_key()
        except ProviderError as e:
            return False, str(e)
        return True, f"key present, model={self._model()}"
