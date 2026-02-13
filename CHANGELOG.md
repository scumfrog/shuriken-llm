# Changelog

## 2.0.0 — Full Rewrite

### Architecture
- Modular package structure (7 modules, 33 files)
- Plugin registry pattern for adapters, tools, detectors, reporters, runners
- YAML-first configuration with matrix expansion
- Type-safe dataclasses throughout

### Adapters
- OpenAI (+ Azure, vLLM, LMStudio via base_url)
- Ollama (local, native tool call support)
- Anthropic (Messages API with system prompt handling)
- Pluggable registry for custom adapters

### Payloads (22 built-in)
- LLM01: 9 prompt injection variants (basic → stealth)
- LLM06: 4 system prompt leak variants
- LLM07: 4 tool abuse variants (email, DB, code, chained)
- LLM08: 1 excessive agency variant
- LLM09: 2 overreliance variants (false facts, false authority)
- Multi-turn: 2 templates (trust-build, context-shift)

### Mutators (9 evasion transforms)
- homoglyph, zwsp, html_entities, base64_wrap, rot13
- markdown_escape, comment_split, language_shift, token_split

### Analysis
- 12 detectors: canary (token + URL), regex, tool exfil, SQLi detection, system leak (3-strategy), refusal, acknowledgment, PII, false-fact, semantic similarity
- Rule-based scoring engine with 6 severity levels and confidence scores

### Tools (8 live)
- web_get, send_webhook, dns_resolve, file_read, file_write, code_exec, send_email (SMTP), db_query (SQLite with auto-seed)
- Policy enforcement: domain blocklist, path traversal protection, code pattern blocklist, private range blocking
- ToolExecutor with execution logging and dry-run mode
- Multi-step tool loop in engine (model → tool → result → model)

### Reporters (5 formats)
- JSON (structured with summary + by_model + by_category)
- Markdown (tables, model comparison, cross-matrix)
- HTML (interactive dashboard, donut/bar charts, filtering, dark theme)
- CSV (flat export for pandas/Jupyter)
- SQLite (append-mode with runs + detections tables)

### Runners (3 backends)
- Sequential (default, deterministic)
- Async (ThreadPoolExecutor, ~Nx speedup for API-bound runs)
- Worker (ProcessPoolExecutor, process isolation)

### Config
- YAML-first with environment variable fallback
- Single scenario, batch list, or matrix expansion
- Multi-turn conversation sequences
- CLI overrides for all settings

---

## 1.0.0 — Original Single-File

- Single Python file (~500 lines)
- OpenAI + Ollama adapters
- 10 payload templates
- Canary + regex detection
- JSON/Markdown output
