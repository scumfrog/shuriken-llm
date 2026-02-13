"""
shuriken.reporters.html_reporter — Self-contained interactive HTML report.

Features:
  - Summary dashboard with severity donut chart
  - Sortable/filterable results table
  - Model comparison bar chart
  - Expandable detail panels
  - No external dependencies — everything inline (CSS + JS)
  - Dark theme
"""
from __future__ import annotations

import html
import json
from typing import Any, Dict, List

from ..core.types import AttackResult, BatchResult, Severity
from . import BaseReporter, register_reporter


_SEVERITY_COLORS = {
    "full_compliance": "#ef4444",
    "partial_leak": "#f97316",
    "acknowledged": "#eab308",
    "refused": "#22c55e",
    "ignored": "#94a3b8",
    "error": "#1e293b",
}


@register_reporter
class HTMLReporter(BaseReporter):
    name = "html"
    extension = ".html"

    def render(self, batch: BatchResult) -> str:
        summary = batch.summary()
        results_json = json.dumps(
            [r.to_dict() for r in batch.results],
            ensure_ascii=False,
        )
        summary_json = json.dumps(summary, ensure_ascii=False)
        by_model_json = json.dumps(
            {
                model: {
                    "total": len(res),
                    "successes": sum(1 for r in res if r.success),
                    "rate": sum(1 for r in res if r.success) / len(res) if res else 0,
                }
                for model, res in batch.by_model().items()
            },
            ensure_ascii=False,
        )

        return _HTML_TEMPLATE.replace(
            "/*__RESULTS_JSON__*/", results_json
        ).replace(
            "/*__SUMMARY_JSON__*/", summary_json
        ).replace(
            "/*__BY_MODEL_JSON__*/", by_model_json
        ).replace(
            "/*__SEVERITY_COLORS__*/", json.dumps(_SEVERITY_COLORS)
        )


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shuriken — Red Team Report</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --text-muted: #94a3b8; --accent: #f97316;
    --red: #ef4444; --orange: #f97316; --yellow: #eab308;
    --green: #22c55e; --gray: #94a3b8; --dark: #1e293b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
         background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
  h1 { color: var(--accent); margin-bottom: 0.5rem; font-size: 1.5rem; }
  h2 { color: var(--text); margin: 2rem 0 1rem; font-size: 1.1rem; border-bottom: 1px solid var(--surface2); padding-bottom: 0.5rem; }

  .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .card { background: var(--surface); border-radius: 8px; padding: 1.2rem; text-align: center; }
  .card .number { font-size: 2rem; font-weight: bold; }
  .card .label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }

  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0; }
  .chart-box { background: var(--surface); border-radius: 8px; padding: 1.5rem; }
  canvas { width: 100% !important; max-height: 280px; }

  .filters { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .filters select, .filters input {
    background: var(--surface); color: var(--text); border: 1px solid var(--surface2);
    border-radius: 6px; padding: 0.5rem 0.8rem; font-family: inherit; font-size: 0.85rem;
  }

  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  thead th { background: var(--surface2); padding: 0.7rem; text-align: left; cursor: pointer;
             position: sticky; top: 0; user-select: none; }
  thead th:hover { background: var(--accent); color: var(--bg); }
  tbody td { padding: 0.6rem 0.7rem; border-bottom: 1px solid var(--surface); }
  tbody tr:hover { background: var(--surface); }

  .severity-badge { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem;
                    font-weight: 600; text-transform: uppercase; }
  .sev-full_compliance { background: var(--red); color: #fff; }
  .sev-partial_leak { background: var(--orange); color: #fff; }
  .sev-acknowledged { background: var(--yellow); color: #000; }
  .sev-refused { background: var(--green); color: #fff; }
  .sev-ignored { background: var(--gray); color: #000; }
  .sev-error { background: var(--dark); color: var(--text-muted); }

  .detail-panel { display: none; background: var(--surface); padding: 1rem; margin: 0.3rem 0;
                  border-radius: 6px; font-size: 0.8rem; max-height: 400px; overflow: auto; }
  .detail-panel.open { display: block; }
  .detail-toggle { cursor: pointer; color: var(--accent); text-decoration: underline; }
  pre { white-space: pre-wrap; word-break: break-all; }

  .detection-list { list-style: none; }
  .detection-list li { padding: 0.2rem 0; }
  .det-hit { color: var(--red); }
  .det-miss { color: var(--text-muted); }

  @media (max-width: 800px) {
    .charts { grid-template-columns: 1fr; }
    .dashboard { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>

<h1>Shuriken — Red Team Report</h1>
<div id="dashboard" class="dashboard"></div>

<div class="charts">
  <div class="chart-box">
    <h2>Severity Distribution</h2>
    <canvas id="severityChart"></canvas>
  </div>
  <div class="chart-box">
    <h2>Model Comparison</h2>
    <canvas id="modelChart"></canvas>
  </div>
</div>

<h2>Results</h2>
<div class="filters">
  <select id="filterSeverity"><option value="">All severities</option></select>
  <select id="filterModel"><option value="">All models</option></select>
  <select id="filterCategory"><option value="">All categories</option></select>
  <input id="filterSearch" type="text" placeholder="Search scenario ID...">
</div>
<table>
  <thead>
    <tr>
      <th data-sort="scenario_id">Scenario</th>
      <th data-sort="severity">Severity</th>
      <th data-sort="model">Model</th>
      <th data-sort="category">Category</th>
      <th data-sort="duration_ms">Duration</th>
      <th>Detections</th>
      <th>Detail</th>
    </tr>
  </thead>
  <tbody id="resultsBody"></tbody>
</table>

<script>
const RESULTS = (/*__RESULTS_JSON__*/ || []);
const SUMMARY = (/*__SUMMARY_JSON__*/ || {});
const BY_MODEL = (/*__BY_MODEL_JSON__*/ || {});
const SEV_COLORS = (/*__SEVERITY_COLORS__*/ || {});

// Dashboard cards
const dash = document.getElementById('dashboard');
const cards = [
  { label: 'Total Runs', number: SUMMARY.total, color: 'var(--text)' },
  { label: 'Successes', number: SUMMARY.successes, color: 'var(--red)' },
  { label: 'Success Rate', number: (SUMMARY.success_rate * 100).toFixed(0) + '%', color: 'var(--accent)' },
  { label: 'Models Tested', number: Object.keys(BY_MODEL).length, color: 'var(--text)' },
];
cards.forEach(c => {
  dash.innerHTML += `<div class="card"><div class="number" style="color:${c.color}">${c.number}</div><div class="label">${c.label}</div></div>`;
});

// Populate filter dropdowns
const sevSet = new Set(), modelSet = new Set(), catSet = new Set();
RESULTS.forEach(r => { sevSet.add(r.severity); modelSet.add(r.model); catSet.add(r.category); });
const addOpts = (sel, vals) => vals.forEach(v => sel.innerHTML += `<option value="${v}">${v}</option>`);
addOpts(document.getElementById('filterSeverity'), [...sevSet].sort());
addOpts(document.getElementById('filterModel'), [...modelSet].sort());
addOpts(document.getElementById('filterCategory'), [...catSet].sort());

// Render table
function renderTable(data) {
  const tbody = document.getElementById('resultsBody');
  tbody.innerHTML = '';
  data.forEach((r, i) => {
    const matched = (r.detections || []).filter(d => d.matched);
    const clean = (r.detections || []).filter(d => !d.matched);
    const detSummary = `<span class="det-hit">${matched.length} hit</span> / <span class="det-miss">${clean.length} clean</span>`;
    const detList = (r.detections || []).map(d =>
      `<li class="${d.matched ? 'det-hit' : 'det-miss'}">${d.matched ? '🔴' : '⚪'} ${esc(d.detector)} — ${esc((d.evidence||'').substring(0,120))}</li>`
    ).join('');
    tbody.innerHTML += `
      <tr>
        <td><code>${esc(r.scenario_id)}</code></td>
        <td><span class="severity-badge sev-${r.severity}">${r.severity}</span></td>
        <td><code>${esc(r.model)}</code></td>
        <td>${esc(r.category)}</td>
        <td>${r.duration_ms}ms</td>
        <td>${detSummary}</td>
        <td><span class="detail-toggle" onclick="toggleDetail(${i})">▸ show</span></td>
      </tr>
      <tr><td colspan="7">
        <div class="detail-panel" id="detail-${i}">
          <strong>Detections:</strong>
          <ul class="detection-list">${detList}</ul>
          <br><strong>Model output:</strong>
          <pre>${esc((r.model_output||'').substring(0, 2000))}</pre>
        </div>
      </td></tr>
    `;
  });
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
function toggleDetail(i) {
  const el = document.getElementById('detail-' + i);
  el.classList.toggle('open');
}

// Filtering
function applyFilters() {
  const sev = document.getElementById('filterSeverity').value;
  const model = document.getElementById('filterModel').value;
  const cat = document.getElementById('filterCategory').value;
  const search = document.getElementById('filterSearch').value.toLowerCase();
  const filtered = RESULTS.filter(r =>
    (!sev || r.severity === sev) &&
    (!model || r.model === model) &&
    (!cat || r.category === cat) &&
    (!search || r.scenario_id.toLowerCase().includes(search))
  );
  renderTable(filtered);
}
document.querySelectorAll('.filters select, .filters input').forEach(el =>
  el.addEventListener('input', applyFilters)
);

// Column sorting
let sortCol = null, sortAsc = true;
document.querySelectorAll('thead th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
    const sorted = [...RESULTS].sort((a, b) => {
      const va = a[col] ?? '', vb = b[col] ?? '';
      if (typeof va === 'number') return sortAsc ? va - vb : vb - va;
      return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    renderTable(sorted);
  });
});

// Charts (pure canvas — no library needed)
function drawDonut(canvasId, data, colors) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const W = canvas.width = canvas.parentElement.clientWidth - 48;
  const H = canvas.height = 260;
  const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 30, r = R * 0.55;
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return;
  let angle = -Math.PI / 2;
  data.forEach(d => {
    const slice = (d.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, R, angle, angle + slice);
    ctx.arc(cx, cy, r, angle + slice, angle, true);
    ctx.closePath();
    ctx.fillStyle = colors[d.label] || '#666';
    ctx.fill();
    // Label
    if (d.value > 0) {
      const mid = angle + slice / 2;
      const lx = cx + (R + 18) * Math.cos(mid);
      const ly = cy + (R + 18) * Math.sin(mid);
      ctx.fillStyle = '#e2e8f0';
      ctx.font = '11px monospace';
      ctx.textAlign = mid > Math.PI / 2 && mid < Math.PI * 1.5 ? 'right' : 'left';
      ctx.fillText(`${d.label} (${d.value})`, lx, ly);
    }
    angle += slice;
  });
  // Center text
  ctx.fillStyle = '#e2e8f0';
  ctx.font = 'bold 24px monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 8);
  ctx.font = '11px monospace';
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('total', cx, cy + 14);
}

function drawBars(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const W = canvas.width = canvas.parentElement.clientWidth - 48;
  const H = canvas.height = 260;
  const labels = Object.keys(data);
  const n = labels.length;
  if (!n) return;
  const barW = Math.min(60, (W - 80) / n - 10);
  const maxVal = Math.max(...labels.map(l => data[l].total), 1);
  const chartH = H - 60, baseY = H - 40;

  labels.forEach((label, i) => {
    const x = 50 + i * (barW + 10);
    const total = data[label].total;
    const succ = data[label].successes;
    const hTotal = (total / maxVal) * chartH;
    const hSucc = (succ / maxVal) * chartH;

    // Total bar
    ctx.fillStyle = '#334155';
    ctx.fillRect(x, baseY - hTotal, barW, hTotal);
    // Success overlay
    ctx.fillStyle = '#ef4444';
    ctx.fillRect(x, baseY - hSucc, barW, hSucc);

    // Label
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px monospace';
    ctx.textAlign = 'center';
    ctx.save();
    ctx.translate(x + barW / 2, baseY + 8);
    ctx.rotate(0.3);
    ctx.fillText(label.length > 12 ? label.slice(0, 12) + '…' : label, 0, 0);
    ctx.restore();

    // Count
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '11px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(`${succ}/${total}`, x + barW / 2, baseY - hTotal - 6);
  });
}

// Initial render
renderTable(RESULTS);
const sevData = Object.entries(SUMMARY.by_severity || {}).map(([k, v]) => ({ label: k, value: v }));
drawDonut('severityChart', sevData, SEV_COLORS);
drawBars('modelChart', BY_MODEL);
</script>
</body>
</html>""".lstrip()
