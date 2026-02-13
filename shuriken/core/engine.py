"""
shuriken.core.engine — Attack execution engine.

Handles:
  - Single-shot execution
  - Multi-turn conversations
  - Batch/matrix runs
  - Canary injection & payload resolution
  - Tool spec construction
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canary import Canary, generate_canary, replace_placeholders
from .types import (
    AdapterResponse,
    AttackCategory,
    AttackResult,
    BatchResult,
    ChatMessage,
    Detection,
    Scenario,
    Severity,
    Turn,
)


# ---------------------------------------------------------------------------
# Tool specs — delegate to tools module
# ---------------------------------------------------------------------------

def _get_tool_specs(tool_names: List[str]) -> Optional[List[Dict[str, Any]]]:
    """Get tool specs from the tools registry."""
    try:
        from ..tools import get_tool_specs
        specs = get_tool_specs(tool_names)
        return specs or None
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------

def _resolve_payload(scenario: Scenario, canary: Canary) -> Optional[str]:
    """Resolve the final payload text, applying canary placeholders."""
    text: Optional[str] = None

    if scenario.payload_file:
        text = Path(scenario.payload_file).read_text(encoding="utf-8", errors="replace")
    elif scenario.payload_text:
        text = scenario.payload_text
    elif scenario.payload_name:
        # Defer to payloads registry (imported lazily to avoid circular)
        try:
            from ..payloads.registry import get_payload
            text = get_payload(scenario.payload_name)
        except (ImportError, KeyError):
            text = None

    if text:
        text = replace_placeholders(text, canary)
        # Apply mutators if any
        if scenario.mutators:
            try:
                from ..payloads.mutators import apply_chain
                text = apply_chain(text, scenario.mutators)
            except ImportError:
                pass  # mutators module not yet available

    return text


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------

def _read_context_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")[:8000]


def build_messages(
    scenario: Scenario,
    poison_text: Optional[str],
) -> List[ChatMessage]:
    """Build the message list for a single-shot or multi-turn scenario."""
    messages: List[ChatMessage] = []

    # System prompt
    if scenario.system_prompt:
        messages.append(ChatMessage(role="system", content=scenario.system_prompt))

    # Context docs (RAG simulation)
    context_parts: List[str] = []
    for i, path in enumerate(scenario.context_files):
        context_parts.append(f"[DOC {i + 1}]\n{_read_context_file(path)}")
    for i, inline in enumerate(scenario.context_inline):
        context_parts.append(f"[DOC inline-{i + 1}]\n{inline[:8000]}")
    if poison_text:
        context_parts.append(f"[DOC INJECTED]\n{poison_text[:8000]}")

    if context_parts:
        messages.append(ChatMessage(
            role="system",
            content="Retrieved documents:\n\n" + "\n\n".join(context_parts),
        ))

    # Single-shot vs multi-turn
    if scenario.turns:
        for turn in scenario.turns:
            role = turn.role if turn.role != "inject" else "user"
            content = turn.content
            if poison_text and "{{POISON}}" in content:
                content = content.replace("{{POISON}}", poison_text)
            messages.append(ChatMessage(role=role, content=content))
    elif scenario.task:
        messages.append(ChatMessage(role="user", content=scenario.task))

    return messages


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _analyze(
    resp: AdapterResponse,
    canary: Canary,
    scenario: Scenario,
    messages_sent: List[Dict[str, Any]] | None = None,
) -> tuple[Severity, List[Detection]]:
    """Analyze adapter response using the full detector + scoring pipeline."""
    if resp.error:
        return Severity.ERROR, [Detection(detector="error", matched=True, evidence=resp.error)]

    from ..analysis.detectors import DetectorContext, run_all_detectors
    from ..analysis.scoring import score_detections

    ctx = DetectorContext(
        response=resp,
        canary=canary,
        scenario=scenario,
        messages_sent=messages_sent or [],
    )
    detections = run_all_detectors(ctx)
    scoring = score_detections(detections)
    return scoring.severity, detections


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_scenario(
    scenario: Scenario,
    adapter: Any,  # BaseAdapter — avoid circular import
    run_index: int = 0,
) -> AttackResult:
    """Execute a single scenario against an adapter and return the result."""
    t0 = time.monotonic()

    # Generate canary
    canary = generate_canary(
        prefix=scenario.canary_prefix,
        base_url=scenario.canary_base_url,
    )

    # Resolve payload
    poison_text = _resolve_payload(scenario, canary)

    # Build messages
    messages = build_messages(scenario, poison_text)

    # Build tool specs from registry
    tools = _get_tool_specs(scenario.tools)

    # Set up tool executor for live/mock execution
    from ..tools import ToolExecutor, ToolContext as TCtx
    tool_ctx = TCtx(
        allow_domains=scenario.allow_domains,
        timeout=10,
        dry_run=False,
    )
    executor = ToolExecutor(ctx=tool_ctx)

    # Call adapter
    resp: AdapterResponse = adapter.chat(
        messages=messages,
        model=scenario.model,
        tools=tools,
        temperature=scenario.temperature,
    )

    # Multi-step tool execution loop:
    # If the model made tool calls, execute them and feed results back
    max_steps = 3
    step = 0
    all_tool_calls = list(resp.tool_calls)

    while resp.tool_calls and step < max_steps:
        step += 1
        tool_results = executor.execute_all(resp.tool_calls)

        # Build tool result messages to feed back
        for tc, tr in zip(resp.tool_calls, tool_results):
            tc_id = None
            if tc.raw and isinstance(tc.raw, dict):
                tc_id = tc.raw.get("id")
            messages.append(ChatMessage(
                role="assistant",
                content=resp.content or "",
            ))
            messages.append(ChatMessage(
                role="tool",
                content=tr.to_message_content(),
                tool_call_id=tc_id,
                name=tc.tool_name,
            ))

        # Call adapter again with tool results
        resp = adapter.chat(
            messages=messages,
            model=scenario.model,
            tools=tools,
            temperature=scenario.temperature,
        )
        all_tool_calls.extend(resp.tool_calls)

    # Merge all tool calls into the final response for analysis
    final_resp = AdapterResponse(
        content=resp.content,
        tool_calls=all_tool_calls,
        raw=resp.raw,
        usage=resp.usage,
        error=resp.error,
    )

    # Analyze
    msgs_sent = [m.to_api_dict() for m in messages]
    severity, detections = _analyze(final_resp, canary, scenario, msgs_sent)
    duration_ms = int((time.monotonic() - t0) * 1000)

    return AttackResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        category=scenario.category,
        adapter=scenario.adapter.value,
        model=scenario.model,
        severity=severity,
        detections=detections,
        model_output=final_resp.content,
        messages_sent=msgs_sent,
        raw_response=final_resp.raw,
        duration_ms=duration_ms,
        run_index=run_index,
        metadata={
            "canary_token": canary.token,
            "canary_url": canary.url,
            "tool_execution_log": tool_ctx.execution_log,
            "tool_steps": step,
        },
    )


def run_batch(
    scenarios: List[Scenario],
    adapter_factory: Any = None,  # callable(scenario) -> adapter
) -> BatchResult:
    """
    Run multiple scenarios, potentially with different adapters.

    Args:
        scenarios: List of Scenario objects.
        adapter_factory: Callable that receives a Scenario and returns a BaseAdapter.
                         If None, uses create_adapter from the adapters module.
    """
    if adapter_factory is None:
        from ..adapters import create_adapter
        def adapter_factory(s: Scenario):
            return create_adapter(s.adapter, model=s.model, base_url=s.base_url)

    results: List[AttackResult] = []
    for scenario in scenarios:
        adapter = adapter_factory(scenario)
        for i in range(scenario.repeat):
            result = run_scenario(scenario, adapter, run_index=i)
            results.append(result)

    return BatchResult(results=results)
