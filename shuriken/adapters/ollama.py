"""
shuriken.adapters.ollama — Local Ollama adapter.

Supports both /api/chat (native) and /v1/chat/completions (OpenAI compat).
Prefers native endpoint for tool-call support on newer Ollama versions.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

from ..core.types import AdapterResponse, AdapterType, ChatMessage
from .base import BaseAdapter


class OllamaAdapter(BaseAdapter):

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(model=model, base_url=base_url, **kwargs)
        self._base_url = base_url or os.environ.get(
            "OLLAMA_HOST", "http://localhost:11434"
        )

    @property
    def adapter_type(self) -> AdapterType:
        return AdapterType.OLLAMA

    @property
    def default_model(self) -> str:
        return "llama3.1"

    def _call(
        self,
        messages: List[ChatMessage],
        model: str,
        tools: Optional[List[Dict[str, Any]]],
        temperature: float,
        **kwargs: Any,
    ) -> AdapterResponse:
        url = f"{self._base_url.rstrip('/')}/api/chat"

        payload: Dict[str, Any] = {
            "model": model,
            "messages": [m.to_api_dict() for m in messages],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = tools

        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, headers=headers, json=payload, timeout=self._timeout)
        data = resp.json()

        if "error" in data:
            return AdapterResponse(error=str(data["error"]), raw=data)

        msg = data.get("message", {})
        content = msg.get("content", "") or data.get("response", "")

        # Ollama native tool calls (v0.4+)
        raw_tool_calls = msg.get("tool_calls", [])
        tool_calls = []
        for tc in raw_tool_calls:
            fn = tc.get("function", {})
            tool_calls.append(
                __import__("shuriken.core.types", fromlist=["ToolCall"]).ToolCall(
                    tool_name=fn.get("name", ""),
                    arguments=fn.get("arguments", {}),
                    raw=tc,
                )
            )

        # Duration from Ollama metrics
        usage: Dict[str, int] = {}
        if "eval_count" in data:
            usage["completion_tokens"] = data["eval_count"]
        if "prompt_eval_count" in data:
            usage["prompt_tokens"] = data["prompt_eval_count"]
        if "total_duration" in data:
            usage["duration_ms"] = data["total_duration"] // 1_000_000  # ns → ms

        return AdapterResponse(
            content=content,
            tool_calls=tool_calls,
            raw=data,
            usage=usage,
        )
