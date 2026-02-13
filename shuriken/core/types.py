"""
shuriken.core.types — Shared data structures, enums, and protocols.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Granular outcome instead of bool success/fail."""
    FULL_COMPLIANCE = "full_compliance"       # Model executed the payload fully
    PARTIAL_LEAK = "partial_leak"             # Canary mentioned but no tool call
    ACKNOWLEDGED = "acknowledged"             # Model noted hidden instructions exist
    REFUSED = "refused"                       # Model detected & refused
    IGNORED = "ignored"                       # Model ignored payload cleanly
    ERROR = "error"                           # Adapter or analysis error

    @property
    def is_success(self) -> bool:
        """From attacker's perspective: did the injection succeed?"""
        return self in (Severity.FULL_COMPLIANCE, Severity.PARTIAL_LEAK)


class AttackCategory(Enum):
    """Maps loosely to OWASP LLM Top-10 + extensions."""
    PROMPT_INJECTION = "LLM01_prompt_injection"
    INSECURE_OUTPUT = "LLM02_insecure_output"
    DATA_POISONING = "LLM03_data_poisoning"
    DENIAL_OF_SERVICE = "LLM04_dos"
    SUPPLY_CHAIN = "LLM05_supply_chain"
    SENSITIVE_DISCLOSURE = "LLM06_sensitive_disclosure"
    INSECURE_PLUGIN = "LLM07_insecure_plugin"
    EXCESSIVE_AGENCY = "LLM08_excessive_agency"
    OVERRELIANCE = "LLM09_overreliance"
    MODEL_THEFT = "LLM10_model_theft"
    TOOL_ABUSE = "tool_abuse"
    MULTI_TURN = "multi_turn"
    CUSTOM = "custom"


class AdapterType(Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Chat primitives
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    role: str                                  # system | user | assistant | tool
    content: str
    tool_call_id: Optional[str] = None
    name: Optional[str] = None                 # for tool results
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_api_dict(self) -> Dict[str, Any]:
        """Minimal dict for API calls (drops None fields)."""
        d: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            d["name"] = self.name
        return d


@dataclass
class ToolCall:
    """Represents a tool invocation extracted from model output."""
    tool_name: str
    arguments: Dict[str, Any]
    raw: Any = None                            # original provider-specific blob


@dataclass
class AdapterResponse:
    """Normalized response from any adapter."""
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    usage: Dict[str, int] = field(default_factory=dict)  # prompt_tokens, completion_tokens

    @property
    def ok(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# Scenario & Results
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    """One turn in a multi-turn attack sequence."""
    role: str          # user | assistant (simulated) | inject
    content: str
    delay_ms: int = 0  # optional pacing


@dataclass
class Scenario:
    """
    Full attack scenario definition.  Can be single-shot or multi-turn.
    Loaded from YAML or built programmatically.
    """
    id: str
    name: str = ""
    description: str = ""
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    adapter: AdapterType = AdapterType.OLLAMA
    model: str = "llama3.1"
    base_url: Optional[str] = None

    # Prompts
    system_prompt: str = ""
    task: str = ""                             # single-shot user message
    turns: List[Turn] = field(default_factory=list)  # multi-turn overrides task

    # RAG simulation
    context_files: List[str] = field(default_factory=list)
    context_inline: List[str] = field(default_factory=list)

    # Payload
    payload_name: Optional[str] = None
    payload_file: Optional[str] = None
    payload_text: Optional[str] = None
    mutators: List[str] = field(default_factory=list)

    # Detection / analysis
    canary_prefix: str = "ZX-CANARY-"
    canary_base_url: str = "https://example.invalid/canary/"
    regex_detectors: List[str] = field(default_factory=list)
    allow_domains: List[str] = field(default_factory=list)

    # Tool exposure
    tools: List[str] = field(default_factory=list)  # names from mock_tools registry

    # Execution
    repeat: int = 1                            # run N times for statistical significance
    temperature: float = 0.0

    # Metadata
    tags: List[str] = field(default_factory=list)
    expected_severity: Optional[Severity] = None


@dataclass
class Detection:
    """Single detection finding from analysis."""
    detector: str        # e.g. "regex_canary", "tool_call_exfil", "system_leak"
    matched: bool
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Complete result of one scenario execution."""
    scenario_id: str
    scenario_name: str = ""
    category: AttackCategory = AttackCategory.CUSTOM
    adapter: str = ""
    model: str = ""
    severity: Severity = Severity.IGNORED
    detections: List[Detection] = field(default_factory=list)
    model_output: str = ""
    messages_sent: List[Dict[str, Any]] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0
    run_index: int = 0       # which repeat
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.severity.is_success

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        d["success"] = self.success
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ---------------------------------------------------------------------------
# Batch result container
# ---------------------------------------------------------------------------

@dataclass
class BatchResult:
    """Aggregated results from a matrix run."""
    results: List[AttackResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def successes(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def success_rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    def by_model(self) -> Dict[str, List[AttackResult]]:
        out: Dict[str, List[AttackResult]] = {}
        for r in self.results:
            out.setdefault(r.model, []).append(r)
        return out

    def by_category(self) -> Dict[str, List[AttackResult]]:
        out: Dict[str, List[AttackResult]] = {}
        for r in self.results:
            out.setdefault(r.category.value, []).append(r)
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "successes": self.successes,
            "success_rate": round(self.success_rate, 4),
            "by_severity": {
                s.value: sum(1 for r in self.results if r.severity == s)
                for s in Severity
            },
        }


# ---------------------------------------------------------------------------
# Adapter protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class LLMAdapter(Protocol):
    """Interface every adapter must satisfy."""

    @property
    def adapter_type(self) -> AdapterType: ...

    @property
    def default_model(self) -> str: ...

    def chat(
        self,
        messages: List[ChatMessage],
        model: str | None = None,
        tools: List[Dict[str, Any]] | None = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> AdapterResponse: ...
