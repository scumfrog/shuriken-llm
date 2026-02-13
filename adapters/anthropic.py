"""
shuriken.adapters.anthropic — Anthropic Messages API adapter.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

from ..core.types import AdapterResponse, AdapterType, ChatMessage, ToolCall
from .base import BaseAdapter


class AnthropicAdapter(BaseAdapter):

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(model=model, base_url=base_url, **kwargs)
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._base_url = base_url or "https://api.anthropic.com"

    @property
    def adapter_type(self) -> AdapterType:
        return AdapterType.ANTHROPIC

    @property
    def default_model(self) -> str:
        return "claude-sonnet-4-20250514"

    def _call(
        self,
        messages: List[ChatMessage],
        model: str,
        tools: Optional[List[Dict[str, Any]]],
        temperature: float,
        **kwargs: Any,
    ) -> AdapterResponse:
        url = f"{self._base_url.rstrip('/')}/v1/messages"

        # Separate system from conversation messages
        system_text = ""
        conv_messages: List[Dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                system_text += ("\n" + m.content if system_text else m.content)
            else:
                conv_messages.append({"role": m.role, "content": m.content})

        # Anthropic requires alternating user/assistant; merge consecutive same-role
        merged = _merge_consecutive(conv_messages)

        payload: Dict[str, Any] = {
            "model": model,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "messages": merged,
            "temperature": temperature,
        }
        if system_text:
            payload["system"] = system_text
        if tools:
            payload["tools"] = _convert_tools_to_anthropic(tools)

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=self._timeout)
        data = resp.json()

        if data.get("type") == "error":
            err = data.get("error", {})
            return AdapterResponse(
                error=err.get("message", str(err)),
                raw=data,
            )

        # Parse content blocks
        content_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content_parts.append(block["text"])
            elif block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    tool_name=block.get("name", ""),
                    arguments=block.get("input", {}),
                    raw=block,
                ))

        usage_raw = data.get("usage", {})
        usage = {
            "prompt_tokens": usage_raw.get("input_tokens", 0),
            "completion_tokens": usage_raw.get("output_tokens", 0),
        }

        return AdapterResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            raw=data,
            usage=usage,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_consecutive(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Anthropic API requires alternating roles.  Merge consecutive same-role msgs."""
    if not messages:
        return [{"role": "user", "content": "(empty)"}]
    merged: List[Dict[str, Any]] = [messages[0]]
    for m in messages[1:]:
        if m["role"] == merged[-1]["role"]:
            merged[-1]["content"] += "\n\n" + m["content"]
        else:
            merged.append(m)
    # Must start with user
    if merged[0]["role"] != "user":
        merged.insert(0, {"role": "user", "content": "(context follows)"})
    return merged


def _convert_tools_to_anthropic(openai_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert OpenAI-style tool specs to Anthropic format."""
    anthropic_tools = []
    for t in openai_tools:
        fn = t.get("function", {})
        anthropic_tools.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return anthropic_tools
