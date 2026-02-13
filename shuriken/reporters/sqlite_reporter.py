"""
shuriken.reporters.sqlite_reporter — SQLite persistent store.

Creates/appends to a SQLite database with two tables:
  - runs: one row per scenario execution
  - detections: one row per detection finding (FK to runs)

Useful for:
  - Historical trend analysis across campaigns
  - SQL-based querying and aggregation
  - Integration with BI tools
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Optional

from ..core.types import BatchResult
from . import BaseReporter, register_reporter


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    scenario_name TEXT,
    category TEXT,
    adapter TEXT,
    model TEXT,
    severity TEXT,
    success INTEGER,
    duration_ms INTEGER,
    run_index INTEGER,
    model_output TEXT,
    error TEXT,
    canary_token TEXT,
    canary_url TEXT,
    raw_response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    detector TEXT NOT NULL,
    matched INTEGER NOT NULL,
    evidence TEXT,
    metadata TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE INDEX IF NOT EXISTS idx_runs_scenario ON runs(scenario_id);
CREATE INDEX IF NOT EXISTS idx_runs_model ON runs(model);
CREATE INDEX IF NOT EXISTS idx_runs_severity ON runs(severity);
CREATE INDEX IF NOT EXISTS idx_detections_run ON detections(run_id);
CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector);
"""


@register_reporter
class SQLiteReporter(BaseReporter):
    name = "sqlite"
    extension = ".db"

    def render(self, batch: BatchResult) -> str:
        # SQLite reporter doesn't render to string — use write() instead
        return f"[SQLiteReporter] {batch.total} results — use write() to persist to .db file"

    def write(self, batch: BatchResult, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        conn = sqlite3.connect(path)
        try:
            conn.executescript(_SCHEMA)

            for r in batch.results:
                cursor = conn.execute(
                    """INSERT INTO runs
                       (scenario_id, scenario_name, category, adapter, model,
                        severity, success, duration_ms, run_index, model_output,
                        error, canary_token, canary_url, raw_response)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        r.scenario_id,
                        r.scenario_name,
                        r.category.value,
                        r.adapter,
                        r.model,
                        r.severity.value,
                        int(r.success),
                        r.duration_ms,
                        r.run_index,
                        r.model_output[:10000] if r.model_output else None,
                        r.error,
                        r.metadata.get("canary_token"),
                        r.metadata.get("canary_url"),
                        json.dumps(r.raw_response, ensure_ascii=False)[:50000],
                    ),
                )
                run_id = cursor.lastrowid

                for d in r.detections:
                    conn.execute(
                        """INSERT INTO detections (run_id, detector, matched, evidence, metadata)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            run_id,
                            d.detector,
                            int(d.matched),
                            d.evidence[:2000] if d.evidence else None,
                            json.dumps(d.metadata, ensure_ascii=False) if d.metadata else None,
                        ),
                    )

            conn.commit()
        finally:
            conn.close()
