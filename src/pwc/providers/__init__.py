from pwc.providers.base import Provider, ProviderError
from pwc.providers.anthropic import AnthropicProvider
from pwc.providers.openai_compat import OpenAICompatProvider
from pwc.providers.mock import MockProvider


def get_provider(name: str, settings: dict) -> Provider:
    name = (name or "mock").lower()
    if name == "anthropic":
        return AnthropicProvider(settings)
    if name in ("openai", "openai_compat", "openai-compatible"):
        return OpenAICompatProvider(settings)
    if name in ("mock", "offline", "local"):
        return MockProvider(settings)
    raise ProviderError(f"unknown provider: {name!r}")


__all__ = ["Provider", "ProviderError", "get_provider",
           "AnthropicProvider", "OpenAICompatProvider", "MockProvider"]
