"""
shuriken.__main__ — CLI entrypoint.

Usage:
    python -m shuriken --config scenario.yaml
    python -m shuriken --adapter ollama --model llama3.1 --task "Summarize" --payload-name indirect_basic
    python -m shuriken --list-payloads
    python -m shuriken --list-mutators
    python -m shuriken --emit-payload indirect_basic --emit-path ./out.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from .core.config import load_scenarios
from .core.engine import run_scenario, run_batch
from .core.types import AttackResult, BatchResult
from .adapters import create_adapter
from .payloads.registry import list_payloads, get_payload
from .payloads.mutators import list_mutators
from .reporters import create_reporter, list_reporters
from .tools import list_tools
from .runners import get_runner, list_runners as list_runner_names


def _write_file(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def main() -> None:
    p = argparse.ArgumentParser(
        prog="shuriken",
        description="Shuriken — LLM Red Team Toolkit",
    )
    p.add_argument("--config", help="Path to YAML config file")
    p.add_argument("--adapter", choices=["openai", "ollama", "anthropic"])
    p.add_argument("--model")
    p.add_argument("--base-url", help="Adapter base URL")
    p.add_argument("--system", help="System prompt override")
    p.add_argument("--task", help="User task/prompt")
    p.add_argument("--context", nargs="*", help="Context file paths (RAG simulation)")
    p.add_argument("--poison", help="Poison file path")
    p.add_argument("--payload-name", choices=list_payloads(), help="Built-in payload name")
    p.add_argument("--allow-domains", help="Comma-separated domain allowlist")
    p.add_argument("--format", choices=list_reporters(), default="json")
    p.add_argument("--output", "-o", help="Output file (default: stdout)")
    p.add_argument("--scenario-id")

    # Utility commands
    p.add_argument("--list-payloads", action="store_true", help="List built-in payloads and exit")
    p.add_argument("--list-mutators", action="store_true", help="List available mutators and exit")
    p.add_argument("--list-reporters", action="store_true", help="List output formats and exit")
    p.add_argument("--list-tools", action="store_true", help="List available tools and exit")
    p.add_argument("--runner", choices=["sequential", "async", "worker"], default="sequential",
                   help="Execution backend (default: sequential)")
    p.add_argument("--workers", type=int, default=None,
                   help="Max parallel workers for async/worker runners")
    p.add_argument("--emit-payload", choices=list_payloads(), help="Write payload template to disk")
    p.add_argument("--emit-path", help="Output path for --emit-payload")

    args = p.parse_args()

    # Utility commands
    if args.list_payloads:
        for name in list_payloads():
            print(f"  {name}")
        sys.exit(0)

    if args.list_mutators:
        for name in list_mutators():
            print(f"  {name}")
        sys.exit(0)

    if args.list_reporters:
        for name in list_reporters():
            print(f"  {name}")
        sys.exit(0)

    if args.list_tools:
        from .tools import get_tool
        for name in list_tools():
            tool = get_tool(name)
            mode = "mock" if tool.is_mock else "live"
            print(f"  {name:20s} [{mode:4s}]  {tool.description[:60]}")
        sys.exit(0)

    if args.emit_payload:
        path = args.emit_path or f"./payloads/{args.emit_payload}.md"
        _write_file(path, get_payload(args.emit_payload))
        print(f"[+] Payload written: {path}")
        sys.exit(0)

    # Build CLI overrides dict
    cli_overrides = {k: v for k, v in vars(args).items() if v is not None}

    # Load scenarios
    try:
        scenarios = load_scenarios(config_path=args.config, cli_overrides=cli_overrides)
    except Exception as e:
        print(f"[!] Config error: {e}", file=sys.stderr)
        sys.exit(2)

    if not scenarios:
        print("[!] No scenarios to run.", file=sys.stderr)
        sys.exit(2)

    # Build adapter factory
    def adapter_factory(scenario):
        return create_adapter(scenario.adapter, model=scenario.model, base_url=scenario.base_url)

    # Progress callback
    def on_progress(progress):
        r = progress.current_result
        icon = "🔴" if r.success else "🟢"
        print(
            f"  {icon} [{progress.completed}/{progress.total}] "
            f"{r.scenario_id} → {r.severity.value} "
            f"({r.model} via {r.adapter}, {r.duration_ms}ms)",
            file=sys.stderr,
        )

    # Execute via runner
    runner = get_runner(args.runner)
    if hasattr(runner, 'max_workers') and args.workers:
        runner.max_workers = args.workers

    batch = runner.run(
        scenarios=scenarios,
        adapter_factory=adapter_factory,
        on_progress=on_progress,
    )

    # Output via reporter
    reporter = create_reporter(args.format)

    # Summary
    summary = batch.summary()
    print(
        f"\n[*] Done: {summary['total']} runs, "
        f"{summary['successes']} succeeded ({summary['success_rate']:.0%}) "
        f"[runner={args.runner}]",
        file=sys.stderr,
    )

    if args.output:
        reporter.write(batch, args.output)
        print(f"[+] Report written: {args.output} ({args.format})", file=sys.stderr)
    else:
        print(reporter.render(batch))


if __name__ == "__main__":
    main()
