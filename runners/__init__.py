"""
shuriken.runners — Execution backends for scenario runs.

Available runners:
  - SequentialRunner: Simple loop, current behavior (default).
  - AsyncRunner: concurrent.futures thread pool for parallel execution.
  - WorkerRunner: Multiprocessing worker pool for CPU-bound analysis.

All runners produce BatchResult and support progress callbacks.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..core.types import AttackResult, BatchResult, Scenario
from ..adapters.base import BaseAdapter


# ---------------------------------------------------------------------------
# Progress callback protocol
# ---------------------------------------------------------------------------

@dataclass
class RunProgress:
    """Progress update emitted after each scenario run."""
    completed: int
    total: int
    current_result: AttackResult
    elapsed_ms: int = 0

    @property
    def pct(self) -> float:
        return self.completed / self.total if self.total else 0.0


ProgressCallback = Callable[[RunProgress], None]


# ---------------------------------------------------------------------------
# Base runner
# ---------------------------------------------------------------------------

class BaseRunner(ABC):
    """All runners implement this interface."""

    name: str = "base"

    @abstractmethod
    def run(
        self,
        scenarios: List[Scenario],
        adapter_factory: Callable[[Scenario], BaseAdapter],
        on_progress: Optional[ProgressCallback] = None,
    ) -> BatchResult:
        ...


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_RUNNERS: Dict[str, type] = {}


def register_runner(cls: type) -> type:
    _RUNNERS[cls.name] = cls
    return cls


def get_runner(name: str) -> BaseRunner:
    if name not in _RUNNERS:
        raise KeyError(f"Unknown runner '{name}'. Available: {list(_RUNNERS)}")
    return _RUNNERS[name]()


def list_runners() -> List[str]:
    return sorted(_RUNNERS.keys())


# Import submodules to trigger registration
from .sequential import SequentialRunner   # noqa: F401,E402
from .async_runner import AsyncRunner      # noqa: F401,E402
from .worker import WorkerRunner           # noqa: F401,E402

__all__ = [
    "BaseRunner",
    "RunProgress",
    "ProgressCallback",
    "get_runner",
    "list_runners",
    "register_runner",
    "SequentialRunner",
    "AsyncRunner",
    "WorkerRunner",
]
