"""
shuriken.adapters.openai — OpenAI / OpenAI-compatible adapter.

Works with: OpenAI, Azure OpenAI, vLLM, LMStudio, any OpenAI-compatible endpoint.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

from ..core.types import AdapterResponse, AdapterType, ChatMessage
from .base import BaseAdapter


class OpenAIAdapter(BaseAdapter):

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(model=model, base_url=base_url, **kwargs)
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._base_url = base_url or os.environ.get(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )

    @property
    def adapter_type(self) -> AdapterType:
        return AdapterType.OPENAI

    @property
    def default_model(self) -> str:
        return "gpt-4o-mini"

    def _call(
        self,
        messages: List[ChatMessage],
        model: str,
        tools: Optional[List[Dict[str, Any]]],
        temperature: float,
        **kwargs: Any,
    ) -> AdapterResponse:
        url = f"{self._base_url.rstrip('/')}/chat/completions"

        payload: Dict[str, Any] = {
            "model": model,
            "messages": [m.to_api_dict() for m in messages],
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = kwargs.get("tool_choice", "auto")

        headers = {
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = requests.post(
            url, headers=headers, json=payload, timeout=self._timeout
        )
        data = resp.json()

        if "error" in data:
            return AdapterResponse(
                error=data["error"].get("message", str(data["error"])),
                raw=data,
            )

        choice = data.get("choices", [{}])[0]
        msg = choice.get("message", {})
        content = msg.get("content") or ""
        tool_calls = self._extract_tool_calls(msg.get("tool_calls"))

        usage_raw = data.get("usage", {})
        usage = {
            "prompt_tokens": usage_raw.get("prompt_tokens", 0),
            "completion_tokens": usage_raw.get("completion_tokens", 0),
        }

        return AdapterResponse(
            content=content,
            tool_calls=tool_calls,
            raw=data,
            usage=usage,
        )
