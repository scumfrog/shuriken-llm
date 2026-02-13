"""
shuriken.reporters.markdown — Markdown report.

Generates a full report with:
  - Executive summary table
  - Model comparison matrix
  - Category breakdown
  - Per-scenario detail blocks
"""
from __future__ import annotations

from typing import List

from ..core.types import AttackResult, BatchResult, Severity
from . import BaseReporter, register_reporter


@register_reporter
class MarkdownReporter(BaseReporter):
    name = "md"
    extension = ".md"

    def render(self, batch: BatchResult) -> str:
        lines: List[str] = []
        s = batch.summary()

        # Header
        lines.append("# 🔴 Shuriken — Red Team Report\n")
        lines.append(f"**Total runs:** {s['total']}  ")
        lines.append(f"**Successes (attacker perspective):** {s['successes']}  ")
        lines.append(f"**Success rate:** {s['success_rate']:.1%}  \n")

        # Severity breakdown
        lines.append("## Severity Breakdown\n")
        lines.append("| Severity | Count | % |")
        lines.append("|----------|------:|--:|")
        for sev in Severity:
            count = s["by_severity"].get(sev.value, 0)
            pct = count / s["total"] * 100 if s["total"] else 0
            icon = _severity_icon(sev)
            lines.append(f"| {icon} {sev.value} | {count} | {pct:.0f}% |")
        lines.append("")

        # Model comparison
        by_model = batch.by_model()
        if len(by_model) > 1:
            lines.append("## Model Comparison\n")
            lines.append("| Model | Runs | Success | Rate | Avg ms |")
            lines.append("|-------|-----:|--------:|-----:|-------:|")
            for model, results in sorted(by_model.items()):
                total = len(results)
                succ = sum(1 for r in results if r.success)
                rate = succ / total if total else 0
                avg_ms = sum(r.duration_ms for r in results) / total if total else 0
                lines.append(f"| `{model}` | {total} | {succ} | {rate:.0%} | {avg_ms:.0f} |")
            lines.append("")

        # Category breakdown
        by_cat = batch.by_category()
        if len(by_cat) > 1:
            lines.append("## Category Breakdown\n")
            lines.append("| Category | Runs | Success | Rate |")
            lines.append("|----------|-----:|--------:|-----:|")
            for cat, results in sorted(by_cat.items()):
                total = len(results)
                succ = sum(1 for r in results if r.success)
                rate = succ / total if total else 0
                lines.append(f"| `{cat}` | {total} | {succ} | {rate:.0%} |")
            lines.append("")

        # Cross-matrix: model × payload (if matrix run)
        payloads = set()
        for r in batch.results:
            pn = r.metadata.get("payload_name") or r.scenario_id
            payloads.add(pn)
        if len(by_model) > 1 and len(payloads) > 1:
            lines.append("## Model × Payload Matrix\n")
            sorted_payloads = sorted(payloads)
            header = "| Model | " + " | ".join(f"`{p}`" for p in sorted_payloads) + " |"
            sep = "|-------|" + "|".join("---:" for _ in sorted_payloads) + "|"
            lines.append(header)
            lines.append(sep)
            for model in sorted(by_model.keys()):
                cells = []
                for payload in sorted_payloads:
                    matching = [
                        r for r in by_model[model]
                        if (r.metadata.get("payload_name") or r.scenario_id) == payload
                    ]
                    if matching:
                        succ = sum(1 for r in matching if r.success)
                        total = len(matching)
                        icon = "🔴" if succ > 0 else "🟢"
                        cells.append(f"{icon} {succ}/{total}")
                    else:
                        cells.append("—")
                lines.append(f"| `{model}` | " + " | ".join(cells) + " |")
            lines.append("")

        # Per-scenario detail
        lines.append("## Scenario Details\n")
        for r in batch.results:
            icon = _severity_icon(r.severity)
            lines.append(f"### {icon} `{r.scenario_id}`")
            if r.scenario_name:
                lines.append(f"*{r.scenario_name}*\n")
            lines.append(f"- **Severity:** `{r.severity.value}`")
            lines.append(f"- **Model:** `{r.model}` via `{r.adapter}`")
            lines.append(f"- **Category:** `{r.category.value}`")
            lines.append(f"- **Duration:** {r.duration_ms}ms")
            if r.error:
                lines.append(f"- **Error:** `{r.error}`")

            # Detections
            matched = [d for d in r.detections if d.matched]
            clean = [d for d in r.detections if not d.matched]
            if matched:
                lines.append("\n**Triggered detections:**\n")
                for d in matched:
                    lines.append(f"- 🔴 **{d.detector}** — {d.evidence[:200]}")
            if clean:
                lines.append(f"\n**Clean detections:** {len(clean)} passed")

            # Model output (truncated)
            if r.model_output:
                output = r.model_output[:1500]
                if len(r.model_output) > 1500:
                    output += "\n... (truncated)"
                lines.append(f"\n<details><summary>Model output</summary>\n\n```\n{output}\n```\n</details>\n")
            lines.append("---\n")

        return "\n".join(lines)


def _severity_icon(sev: Severity) -> str:
    return {
        Severity.FULL_COMPLIANCE: "🔴",
        Severity.PARTIAL_LEAK: "🟠",
        Severity.ACKNOWLEDGED: "🟡",
        Severity.REFUSED: "🟢",
        Severity.IGNORED: "⚪",
        Severity.ERROR: "⚫",
    }.get(sev, "❓")
