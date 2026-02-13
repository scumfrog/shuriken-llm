"""
shuriken.runners.sequential — Single-threaded sequential execution.

Simple, deterministic, easy to debug.  Default runner.
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from ..core.types import AttackResult, BatchResult, Scenario
from ..core.engine import run_scenario
from ..adapters.base import BaseAdapter
from . import BaseRunner, ProgressCallback, RunProgress, register_runner


@register_runner
class SequentialRunner(BaseRunner):
    name = "sequential"

    def run(
        self,
        scenarios: List[Scenario],
        adapter_factory: Callable[[Scenario], BaseAdapter],
        on_progress: Optional[ProgressCallback] = None,
    ) -> BatchResult:
        results: List[AttackResult] = []
        tasks = _expand_repeats(scenarios)
        total = len(tasks)
        t0 = time.monotonic()

        for idx, (scenario, run_index) in enumerate(tasks):
            adapter = adapter_factory(scenario)
            result = run_scenario(scenario, adapter, run_index=run_index)
            results.append(result)

            if on_progress:
                on_progress(RunProgress(
                    completed=idx + 1,
                    total=total,
                    current_result=result,
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                ))

        return BatchResult(results=results)


def _expand_repeats(scenarios: List[Scenario]) -> List[tuple[Scenario, int]]:
    """Expand scenario repeats into (scenario, run_index) pairs."""
    tasks = []
    for s in scenarios:
        for i in range(s.repeat):
            tasks.append((s, i))
    return tasks
