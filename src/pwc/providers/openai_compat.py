"""OpenAI-compatible Chat Completions provider (works with many local servers)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from pwc.providers.base import Provider, ProviderError


class OpenAICompatProvider(Provider):
    name = "openai_compat"

    def _base_url(self) -> str:
        return self.settings.get("base_url", "https://api.openai.com/v1").rstrip("/")

    def _api_key(self) -> str:
        return os.environ.get("OPENAI_API_KEY") or self.settings.get("api_key", "")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self.settings.get("model", "gpt-4o-mini"),
            "max_tokens": int(self.settings.get("max_tokens", 1024)),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode("utf-8")
        req = urllib.request.Request(f"{self._base_url()}/chat/completions",
                                     data=body, method="POST")
        req.add_header("content-type", "application/json")
        key = self._api_key()
        if key:
            req.add_header("authorization", f"Bearer {key}")
        try:
            with urllib.request.urlopen(req, timeout=float(self.settings.get("timeout", 30))) as r:
                data = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise ProviderError(f"OpenAI-compat HTTP {e.code}: "
                                f"{e.read().decode('utf-8', 'replace')[:300]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise ProviderError(f"OpenAI-compat network error: {e}") from e
        try:
            return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError) as e:
            raise ProviderError(f"unexpected response shape: {e}") from e

    def health(self) -> tuple[bool, str]:
        base = self._base_url()
        if "openai.com" in base and not self._api_key():
            return False, "OPENAI_API_KEY not set"
        return True, f"base_url={base}"
