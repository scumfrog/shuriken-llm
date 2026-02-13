"""
shuriken.tools — Tool registry, base protocol, and executor.

Tools come in two flavors:
  - **Live tools**: Actually execute (web_get does a real HTTP call, code_exec runs code).
    Used for end-to-end validation of attack chains.
  - **Mock tools**: Log the invocation but don't execute. Return canned responses.
    Used for detection-only testing.

Every tool registers itself and exposes an OpenAI-compatible function spec
so adapters can pass it to the model.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type

from ..core.types import ToolCall


# ---------------------------------------------------------------------------
# Execution context & result
# ---------------------------------------------------------------------------

@dataclass
class ToolContext:
    """Runtime context passed to every tool execution."""
    sandbox_dir: str = "/tmp/shuriken-sandbox"   # chroot for file ops
    allow_domains: List[str] = field(default_factory=list)
    block_domains: List[str] = field(default_factory=list)
    canary_listener_url: Optional[str] = None     # webhook to detect real exfil
    timeout: int = 10
    dry_run: bool = False                          # if True, all live tools behave as mocks
    execution_log: List[Dict[str, Any]] = field(default_factory=list)

    # SMTP config for send_email (live)
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = False
    smtp_from: str = "shuriken@redteam.invalid"

    # SQLite DB path for db_query (live). Created automatically in sandbox if None.
    db_path: Optional[str] = None


@dataclass
class ToolResult:
    """Result from tool execution."""
    tool_name: str
    success: bool
    output: str                    # what gets fed back to the model
    executed: bool = False         # True if live execution happened
    blocked: bool = False          # True if policy blocked execution
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_message_content(self) -> str:
        """Format for feeding back to the model as a tool result."""
        return self.output


# ---------------------------------------------------------------------------
# Base tool
# ---------------------------------------------------------------------------

class BaseTool(ABC):
    """All tools implement this."""

    name: str = "base"
    description: str = ""
    is_mock: bool = False

    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """Return JSON Schema for the tool's parameters."""
        ...

    @abstractmethod
    def execute(self, arguments: Dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Execute the tool with given arguments."""
        ...

    def to_openai_spec(self) -> Dict[str, Any]:
        """Generate OpenAI-compatible function tool spec."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema(),
            },
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_TOOLS: Dict[str, BaseTool] = {}


def register_tool(tool: BaseTool) -> BaseTool:
    _TOOLS[tool.name] = tool
    return tool


def get_tool(name: str) -> BaseTool:
    if name not in _TOOLS:
        raise KeyError(f"Unknown tool '{name}'. Available: {list(_TOOLS)}")
    return _TOOLS[name]


def list_tools() -> List[str]:
    return sorted(_TOOLS.keys())


def get_tool_specs(names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Get OpenAI-compatible specs for selected (or all) tools."""
    targets = names or list(_TOOLS.keys())
    return [_TOOLS[n].to_openai_spec() for n in targets if n in _TOOLS]


# ---------------------------------------------------------------------------
# Executor — processes tool calls from model responses
# ---------------------------------------------------------------------------

class ToolExecutor:
    """
    Processes tool calls from model output.

    In a live attack chain:
      1. Model responds with tool_calls
      2. Executor runs each tool (live or mock)
      3. Results are fed back to the model
      4. Model continues (multi-step)

    The executor logs every invocation for analysis.
    """

    def __init__(self, ctx: Optional[ToolContext] = None):
        self.ctx = ctx or ToolContext()

    def execute_call(self, call: ToolCall) -> ToolResult:
        """Execute a single tool call."""
        try:
            tool = get_tool(call.tool_name)
        except KeyError:
            result = ToolResult(
                tool_name=call.tool_name,
                success=False,
                output=f"Error: unknown tool '{call.tool_name}'",
                metadata={"error": "unknown_tool"},
            )
            self._log(call, result)
            return result

        # Dry-run mode: all tools become mocks
        if self.ctx.dry_run and not tool.is_mock:
            result = ToolResult(
                tool_name=call.tool_name,
                success=True,
                output=f"[DRY RUN] {call.tool_name} called with: {call.arguments}",
                executed=False,
                metadata={"dry_run": True, "arguments": call.arguments},
            )
            self._log(call, result)
            return result

        try:
            result = tool.execute(call.arguments, self.ctx)
        except Exception as e:
            result = ToolResult(
                tool_name=call.tool_name,
                success=False,
                output=f"Error executing {call.tool_name}: {e}",
                metadata={"exception": str(e)},
            )

        self._log(call, result)
        return result

    def execute_all(self, calls: List[ToolCall]) -> List[ToolResult]:
        """Execute all tool calls and return results."""
        return [self.execute_call(c) for c in calls]

    def _log(self, call: ToolCall, result: ToolResult) -> None:
        """Append to execution log for analysis."""
        self.ctx.execution_log.append({
            "tool_name": call.tool_name,
            "arguments": call.arguments,
            "success": result.success,
            "executed": result.executed,
            "blocked": result.blocked,
            "output_preview": result.output[:500],
            "metadata": result.metadata,
        })


# Import submodules to trigger registration
from . import live_tools  # noqa: F401,E402
from . import mock_tools  # noqa: F401,E402

__all__ = [
    "BaseTool",
    "ToolContext",
    "ToolResult",
    "ToolExecutor",
    "register_tool",
    "get_tool",
    "list_tools",
    "get_tool_specs",
]
