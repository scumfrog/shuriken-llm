"""
shuriken.reporters.csv_reporter — CSV flat export.

One row per scenario run.  Designed for import into spreadsheets, pandas, or SIEM.
Detections are flattened into a semicolon-separated string.
"""
from __future__ import annotations

import csv
import io
from typing import List

from ..core.types import BatchResult
from . import BaseReporter, register_reporter


_COLUMNS = [
    "scenario_id",
    "scenario_name",
    "category",
    "adapter",
    "model",
    "severity",
    "success",
    "duration_ms",
    "run_index",
    "detections_hit",
    "detections_clean",
    "detections_detail",
    "model_output_preview",
    "error",
    "canary_token",
    "canary_url",
]


@register_reporter
class CSVReporter(BaseReporter):
    name = "csv"
    extension = ".csv"

    def render(self, batch: BatchResult) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for r in batch.results:
            matched = [d for d in r.detections if d.matched]
            clean = [d for d in r.detections if not d.matched]
            detail = "; ".join(
                f"{d.detector}={d.evidence[:80]}" for d in matched
            )
            writer.writerow({
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "category": r.category.value,
                "adapter": r.adapter,
                "model": r.model,
                "severity": r.severity.value,
                "success": r.success,
                "duration_ms": r.duration_ms,
                "run_index": r.run_index,
                "detections_hit": len(matched),
                "detections_clean": len(clean),
                "detections_detail": detail,
                "model_output_preview": (r.model_output or "")[:300],
                "error": r.error or "",
                "canary_token": r.metadata.get("canary_token", ""),
                "canary_url": r.metadata.get("canary_url", ""),
            })

        return buf.getvalue()
