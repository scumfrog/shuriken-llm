"""
shuriken.reporters — Report generation from attack results.

Supports: JSON, Markdown, HTML (interactive), CSV, SQLite.
All reporters implement BaseReporter and can output to stdout or file.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from ..core.types import AttackResult, BatchResult


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseReporter(ABC):
    """All reporters implement this interface."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def render(self, batch: BatchResult) -> str:
        """Render batch results to a string."""
        ...

    def write(self, batch: BatchResult, path: str) -> None:
        """Render and write to file."""
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        content = self.render(batch)
        mode = "w"
        enc = "utf-8"
        # SQLite reporter overrides write() directly
        with open(path, mode, encoding=enc) as f:
            f.write(content)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REPORTERS: Dict[str, Type[BaseReporter]] = {}


def register_reporter(cls: Type[BaseReporter]) -> Type[BaseReporter]:
    """Class decorator to register a reporter."""
    _REPORTERS[cls.name] = cls
    return cls


def get_reporter(name: str) -> BaseReporter:
    if name not in _REPORTERS:
        raise KeyError(f"Unknown reporter '{name}'. Available: {list(_REPORTERS)}")
    return _REPORTERS[name]()


def list_reporters() -> List[str]:
    return sorted(_REPORTERS.keys())


def create_reporter(name: str) -> BaseReporter:
    return get_reporter(name)


# Import submodules to trigger registration
from . import json_reporter  # noqa: F401,E402
from . import markdown       # noqa: F401,E402
from . import html_reporter  # noqa: F401,E402
from . import csv_reporter   # noqa: F401,E402
from . import sqlite_reporter  # noqa: F401,E402

__all__ = [
    "BaseReporter",
    "register_reporter",
    "get_reporter",
    "list_reporters",
    "create_reporter",
]
