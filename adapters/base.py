"""
shuriken.adapters.base — Abstract base for LLM adapters.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.types import (
    AdapterResponse,
    AdapterType,
    ChatMessage,
    ToolCall,
)


class BaseAdapter(ABC):
    """
    All adapters inherit from this.  Provides:
      - Retry with backoff
      - Timing
      - Common response normalization helpers
    """

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 2,
        timeout: int = 120,
        **kwargs: Any,
    ):
        self._model = model or self.default_model
        self._base_url = base_url
        self._max_retries = max_retries
        self._timeout = timeout
        self._extra = kwargs

    # -- Protocol properties --------------------------------------------------

    @property
    @abstractmethod
    def adapter_type(self) -> AdapterType: ...

    @property
    @abstractmethod
    def default_model(self) -> str: ...

    # -- Core method to implement ---------------------------------------------

    @abstractmethod
    def _call(
        self,
        messages: List[ChatMessage],
        model: str,
        tools: Optional[List[Dict[str, Any]]],
        temperature: float,
        **kwargs: Any,
    ) -> AdapterResponse:
        """Provider-specific HTTP call.  Must NOT retry internally."""
        ...

    # -- Public chat with retry & timing --------------------------------------

    def chat(
        self,
        messages: List[ChatMessage],
        model: str | None = None,
        tools: List[Dict[str, Any]] | None = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        effective_model = model or self._model
        last_error: Optional[str] = None

        for attempt in range(1, self._max_retries + 2):  # +2 because range is exclusive and attempt 1 is first try
            t0 = time.monotonic()
            try:
                resp = self._call(messages, effective_model, tools, temperature, **kwargs)
                resp.usage.setdefault("duration_ms", int((time.monotonic() - t0) * 1000))
                return resp
            except Exception as e:
                last_error = f"attempt {attempt}: {e}"
                if attempt <= self._max_retries:
                    time.sleep(min(2 ** attempt, 10))  # exp backoff, cap 10s

        return AdapterResponse(error=f"all retries failed — {last_error}")

    # -- Helpers for subclasses -----------------------------------------------

    @staticmethod
    def _extract_tool_calls(raw_calls: Optional[List[Dict[str, Any]]]) -> List[ToolCall]:
        """Parse OpenAI-style tool_calls array."""
        if not raw_calls:
            return []
        import json as _json
        calls = []
        for tc in raw_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = _json.loads(fn.get("arguments", "{}"))
            except Exception:
                args = {"_raw": fn.get("arguments")}
            calls.append(ToolCall(tool_name=name, arguments=args, raw=tc))
        return calls
