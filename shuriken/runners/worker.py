"""
shuriken.runners.worker — Multiprocessing worker pool.

Uses ProcessPoolExecutor for true parallelism with process isolation.
Each scenario runs in its own process, which provides:
  - Real isolation (crash in one doesn't kill others)
  - Better for CPU-bound analysis (semantic similarity, etc.)
  - Memory isolation (each worker gets its own copy)

Trade-off: higher overhead per task (process spawn), and scenarios
must be picklable — which they are since they're pure dataclasses.

For pure I/O-bound API calls, AsyncRunner (threads) is faster.
Use WorkerRunner when:
  - You need process isolation for code_exec tool
  - Analysis is CPU-heavy (semantic embeddings)
  - You're running untrusted scenario configs
"""
from __future__ import annotations

import time
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

from ..core.types import AttackResult, BatchResult, Scenario, Severity, Detection
from ..adapters.base import BaseAdapter
from . import BaseRunner, ProgressCallback, RunProgress, register_runner


# ---------------------------------------------------------------------------
# Worker function (must be top-level for pickling)
# ---------------------------------------------------------------------------

def _run_one(scenario_dict: dict, run_index: int) -> dict:
    """
    Execute a single scenario in a worker process.

    Takes and returns dicts (not dataclasses) to avoid pickle issues
    with complex objects across process boundaries.
    """
    try:
        from ..core.types import Scenario as ScenarioClass
        from ..core.types import AdapterType, AttackCategory, Severity as SeverityEnum, Turn
        from ..core.engine import run_scenario
        from ..adapters import create_adapter

        # Reconstruct scenario from dict
        scenario = ScenarioClass(
            id=scenario_dict["id"],
            name=scenario_dict.get("name", ""),
            description=scenario_dict.get("description", ""),
            category=AttackCategory(scenario_dict.get("category", "custom")),
            adapter=AdapterType(scenario_dict.get("adapter", "ollama")),
            model=scenario_dict.get("model", "llama3.1"),
            base_url=scenario_dict.get("base_url"),
            system_prompt=scenario_dict.get("system_prompt", ""),
            task=scenario_dict.get("task", ""),
            turns=[Turn(**t) for t in scenario_dict.get("turns", [])],
            context_files=scenario_dict.get("context_files", []),
            context_inline=scenario_dict.get("context_inline", []),
            payload_name=scenario_dict.get("payload_name"),
            payload_file=scenario_dict.get("payload_file"),
            payload_text=scenario_dict.get("payload_text"),
            mutators=scenario_dict.get("mutators", []),
            canary_prefix=scenario_dict.get("canary_prefix", "ZX-CANARY-"),
            canary_base_url=scenario_dict.get("canary_base_url", "https://example.invalid/canary/"),
            regex_detectors=scenario_dict.get("regex_detectors", []),
            allow_domains=scenario_dict.get("allow_domains", []),
            tools=scenario_dict.get("tools", []),
            repeat=1,  # already expanded
            temperature=scenario_dict.get("temperature", 0.0),
            tags=scenario_dict.get("tags", []),
        )

        adapter = create_adapter(scenario.adapter, model=scenario.model, base_url=scenario.base_url)
        result = run_scenario(scenario, adapter, run_index=run_index)
        return result.to_dict()

    except Exception as e:
        return {
            "scenario_id": scenario_dict.get("id", "unknown"),
            "scenario_name": scenario_dict.get("name", ""),
            "category": scenario_dict.get("category", "custom"),
            "adapter": scenario_dict.get("adapter", "unknown"),
            "model": scenario_dict.get("model", "unknown"),
            "severity": "error",
            "success": False,
            "detections": [{"detector": "worker_error", "matched": True, "evidence": str(e), "metadata": {}}],
            "model_output": "",
            "messages_sent": [],
            "raw_response": {},
            "error": str(e),
            "duration_ms": 0,
            "run_index": run_index,
            "metadata": {},
        }


def _scenario_to_dict(s: Scenario) -> dict:
    """Serialize scenario to a plain dict for cross-process transfer."""
    return {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "category": s.category.value,
        "adapter": s.adapter.value,
        "model": s.model,
        "base_url": s.base_url,
        "system_prompt": s.system_prompt,
        "task": s.task,
        "turns": [{"role": t.role, "content": t.content, "delay_ms": t.delay_ms} for t in s.turns],
        "context_files": s.context_files,
        "context_inline": s.context_inline,
        "payload_name": s.payload_name,
        "payload_file": s.payload_file,
        "payload_text": s.payload_text,
        "mutators": s.mutators,
        "canary_prefix": s.canary_prefix,
        "canary_base_url": s.canary_base_url,
        "regex_detectors": s.regex_detectors,
        "allow_domains": s.allow_domains,
        "tools": s.tools,
        "temperature": s.temperature,
        "tags": s.tags,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

@register_runner
class WorkerRunner(BaseRunner):
    """Multiprocessing worker pool with process isolation."""

    name = "worker"

    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max_workers or max(1, mp.cpu_count() - 1)

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
        workers = min(workers, total)

        results: List[AttackResult] = []
        completed = 0
        t0 = time.monotonic()

        with ProcessPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_run_one, _scenario_to_dict(scenario), run_index): (scenario, run_index)
                for scenario, run_index in tasks
            }

            for future in as_completed(future_map):
                scenario, run_index = future_map[future]
                try:
                    result_dict = future.result(timeout=300)
                    result = _dict_to_result(result_dict)
                except Exception as e:
                    result = AttackResult(
                        scenario_id=scenario.id,
                        scenario_name=scenario.name,
                        category=scenario.category,
                        adapter=scenario.adapter.value,
                        model=scenario.model,
                        severity=Severity.ERROR,
                        detections=[Detection(
                            detector="worker_error",
                            matched=True,
                            evidence=str(e),
                        )],
                        error=str(e),
                        run_index=run_index,
                    )

                results.append(result)
                completed += 1

                if on_progress:
                    on_progress(RunProgress(
                        completed=completed,
                        total=total,
                        current_result=result,
                        elapsed_ms=int((time.monotonic() - t0) * 1000),
                    ))

        results.sort(key=lambda r: (r.scenario_id, r.run_index))
        return BatchResult(results=results)


def _dict_to_result(d: dict) -> AttackResult:
    """Reconstruct AttackResult from dict returned by worker."""
    from ..core.types import AttackCategory, Severity as SevEnum

    sev = SevEnum.ERROR
    for s in SevEnum:
        if s.value == d.get("severity"):
            sev = s
            break

    cat = AttackCategory.CUSTOM
    for c in AttackCategory:
        if c.value == d.get("category"):
            cat = c
            break

    detections = [
        Detection(
            detector=det.get("detector", ""),
            matched=det.get("matched", False),
            evidence=det.get("evidence", ""),
            metadata=det.get("metadata", {}),
        )
        for det in d.get("detections", [])
    ]

    return AttackResult(
        scenario_id=d.get("scenario_id", ""),
        scenario_name=d.get("scenario_name", ""),
        category=cat,
        adapter=d.get("adapter", ""),
        model=d.get("model", ""),
        severity=sev,
        detections=detections,
        model_output=d.get("model_output", ""),
        messages_sent=d.get("messages_sent", []),
        raw_response=d.get("raw_response", {}),
        error=d.get("error"),
        duration_ms=d.get("duration_ms", 0),
        run_index=d.get("run_index", 0),
        metadata=d.get("metadata", {}),
    )


def _expand_repeats(scenarios: List[Scenario]) -> List[tuple[Scenario, int]]:
    tasks = []
    for s in scenarios:
        for i in range(s.repeat):
            tasks.append((s, i))
    return tasks
