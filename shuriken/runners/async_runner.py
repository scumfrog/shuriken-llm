"""
shuriken.runners.async_runner — Thread-pool parallel execution.

Uses concurrent.futures.ThreadPoolExecutor for I/O-bound parallelism.
Ideal for network-bound LLM API calls — the main bottleneck in batch runs.

Thread-safe progress reporting via lock.
"""
from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from ..core.types import AttackResult, BatchResult, Scenario
from ..core.engine import run_scenario
from ..adapters.base import BaseAdapter
from . import BaseRunner, ProgressCallback, RunProgress, register_runner


@register_runner
class AsyncRunner(BaseRunner):
    """Parallel execution via thread pool."""

    name = "async"

    def __init__(self, max_workers: int = 8):
        self.max_workers = max_workers

    def run(
        self,
        scenarios: List[Scenario],
        adapter_factory: Callable[[Scenario], BaseAdapter],
        on_progress: Optional[ProgressCallback] = None,
        max_workers: Optional[int] = None,
    ) -> BatchResult:
        tasks = _expand_repeats(scenarios)
        total = len(tasks)

        if total == 0:
            return BatchResult()

        workers = max_workers or self.max_workers
        # Don't spawn more workers than tasks
        workers = min(workers, total)

        results: List[AttackResult] = []
        lock = threading.Lock()
        completed = 0
        t0 = time.monotonic()

        def execute_one(scenario: Scenario, run_index: int) -> AttackResult:
            adapter = adapter_factory(scenario)
            return run_scenario(scenario, adapter, run_index=run_index)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(execute_one, scenario, run_index): (scenario, run_index)
                for scenario, run_index in tasks
            }

            for future in as_completed(future_map):
                scenario, run_index = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    # Create error result for failed runs
                    from ..core.types import Severity, Detection
                    result = AttackResult(
                        scenario_id=scenario.id,
                        scenario_name=scenario.name,
                        category=scenario.category,
                        adapter=scenario.adapter.value,
                        model=scenario.model,
                        severity=Severity.ERROR,
                        detections=[Detection(
                            detector="runner_error",
                            matched=True,
                            evidence=str(e),
                        )],
                        error=str(e),
                        run_index=run_index,
                    )

                with lock:
                    results.append(result)
                    completed += 1

                    if on_progress:
                        on_progress(RunProgress(
                            completed=completed,
                            total=total,
                            current_result=result,
                            elapsed_ms=int((time.monotonic() - t0) * 1000),
                        ))

        # Sort results by scenario_id + run_index for deterministic output
        results.sort(key=lambda r: (r.scenario_id, r.run_index))
        return BatchResult(results=results)


def _expand_repeats(scenarios: List[Scenario]) -> List[tuple[Scenario, int]]:
    tasks = []
    for s in scenarios:
        for i in range(s.repeat):
            tasks.append((s, i))
    return tasks
