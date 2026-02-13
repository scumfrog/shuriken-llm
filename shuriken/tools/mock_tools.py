"""
shuriken.tools.mock_tools — Base class for user-defined mock tools.

Provides MockTool as a base for creating custom non-executing tools.
Users can subclass MockTool and register their own mocks for
environment-specific integrations (Slack, Jira, ServiceNow, etc.).

Example:
    from shuriken.tools import register_tool
    from shuriken.tools.mock_tools import MockTool

    class MySlackMock(MockTool):
        name = "slack_post"
        description = "Post to a Slack channel."
        _canned = "Message posted."

        def parameters_schema(self):
            return {
                "type": "object",
                "properties": {"channel": {"type": "string"}, "message": {"type": "string"}},
                "required": ["channel", "message"],
            }

    register_tool(MySlackMock())
"""
from __future__ import annotations

from typing import Any, Dict

from . import BaseTool, ToolContext, ToolResult


class MockTool(BaseTool):
    """Base for non-executing tools.  Logs calls, returns canned response."""

    is_mock = True
    _canned: str = "OK"

    def parameters_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}

    def execute(self, arguments: Dict[str, Any], ctx: ToolContext) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            success=True,
            executed=False,
            output=self._canned,
            metadata={"mock": True, "arguments": arguments},
        )
