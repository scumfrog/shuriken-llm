"""
shuriken.adapters — Adapter registry and factory.

Usage:
    from shuriken.adapters import create_adapter, AdapterType
    adapter = create_adapter(AdapterType.OPENAI, model="gpt-4o-mini")
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Type

from ..core.types import AdapterType, LLMAdapter
from .base import BaseAdapter
from .openai import OpenAIAdapter
from .ollama import OllamaAdapter
from .anthropic import AnthropicAdapter


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[AdapterType, Type[BaseAdapter]] = {
    AdapterType.OPENAI: OpenAIAdapter,
    AdapterType.OLLAMA: OllamaAdapter,
    AdapterType.ANTHROPIC: AnthropicAdapter,
}


def register_adapter(adapter_type: AdapterType, cls: Type[BaseAdapter]) -> None:
    """Register a custom adapter class."""
    _REGISTRY[adapter_type] = cls


def create_adapter(
    adapter_type: AdapterType | str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> BaseAdapter:
    """
    Factory: create an adapter instance by type.

    Args:
        adapter_type: AdapterType enum or string ("openai", "ollama", "anthropic")
        model: Model name override
        base_url: API endpoint override
        **kwargs: Passed to adapter constructor (api_key, timeout, etc.)
    """
    if isinstance(adapter_type, str):
        try:
            adapter_type = AdapterType(adapter_type.lower())
        except ValueError:
            raise ValueError(
                f"Unknown adapter type '{adapter_type}'. "
                f"Available: {[a.value for a in _REGISTRY]}"
            )

    cls = _REGISTRY.get(adapter_type)
    if cls is None:
        raise ValueError(
            f"No adapter registered for '{adapter_type.value}'. "
            f"Use register_adapter() to add custom adapters."
        )

    return cls(model=model, base_url=base_url, **kwargs)


__all__ = [
    "create_adapter",
    "register_adapter",
    "BaseAdapter",
    "OpenAIAdapter",
    "OllamaAdapter",
    "AnthropicAdapter",
]
