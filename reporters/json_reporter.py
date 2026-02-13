"""
shuriken.reporters.json_reporter — JSON output.

Produces a structured JSON document with summary + per-result details.
Useful for CI/CD pipelines, SIEM ingestion, or downstream tooling.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from ..core.types import BatchResult
from . import BaseReporter, register_reporter


@register_reporter
class JSONReporter(BaseReporter):
    name = "json"
    extension = ".json"

    def render(self, batch: BatchResult) -> str:
        output: Dict[str, Any] = {
            "shuriken_version": "2.0.0",
            "summary": batch.summary(),
            "by_model": {
                model: {
                    "total": len(results),
                    "successes": sum(1 for r in results if r.success),
                    "results": [r.to_dict() for r in results],
                }
                for model, results in batch.by_model().items()
            },
            "by_category": {
                cat: {
                    "total": len(results),
                    "successes": sum(1 for r in results if r.success),
                }
                for cat, results in batch.by_category().items()
            },
            "results": [r.to_dict() for r in batch.results],
        }
        return json.dumps(output, ensure_ascii=False, indent=2)
