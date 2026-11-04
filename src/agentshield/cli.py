"""Command-line entry points for configuration, discovery, and bounded runs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from agentshield import __version__
from agentshield.adapters.http import HttpAgentAdapter
from agentshield.adapters.mock import MockAgentAdapter
from agentshield.adapters.fixtures import MCPConnectedMockAdapter, RAGMockAdapter
from agentshield.adapters.mock_mcp_server import serve_mock_mcp
from agentshield.config import load_config
from agentshield.config.environment import load_local_environment
from agentshield.discovery.mcp import ToolMetadata, discover_tools, metadata_changes
from agentshield.discovery.streamable_http import discover_remote_tools, invoke_remote_tool
from agentshield.errors import AgentShieldError
from agentshield.execution.promptfoo import write_promptfoo_config
from agentshield.execution.promptfoo_runner import run_promptfoo
from agentshield.execution.runner import RunBudget, RunResult, redact, run_cases
from agentshield.evaluation.policy import Finding, thresholds_violated
from agentshield.evaluation.groq_judge import judge_semantics
from agentshield.generation.corpus import AttackCase, load_baseline
from agentshield.generation.groq import generate_variants
from agentshield.reporting.reports import compare_reports, write_html_report, write_json_report


def _adapter(config):
    if config.target.adapter == "mock":
        return MockAgentAdapter(config)
    if config.target.adapter == "mock_rag":
        return RAGMockAdapter(config)
    if config.target.adapter == "mock_mcp":
        return MCPConnectedMockAdapter(config)
    if config.target.adapter == "http":
        return HttpAgentAdapter(config)
    raise AgentShieldError("Supported target adapters are 'mock' and 'http'.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield", description="Bounded red-team testing for authorized LLM agents")
    parser.add_argument("--version", action="version", version=f"AgentShield {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-config", help="Validate configuration and target scope")
    validate.add_argument("config")
    discover = commands.add_parser("discover", help="Classify the bundled synthetic MCP fixture")
    discover.add_argument("--config", required=True)
    discover.add_argument("--output")
    discover.add_argument("--previous")
    discover.add_argument("--live", action="store_true", help="Read-only tools/list from mcp.server_url")
    invoke = commands.add_parser("invoke-mcp-tool", help="Invoke one explicitly allowlisted tool on a loopback mock MCP server")
    invoke.add_argument("--config", required=True)
    invoke.add_argument("--tool", required=True)
    invoke.add_argument("--arguments-json", default="{}")
    invoke.add_argument("--output", default="reports/mcp-invocation.json")
    mock_mcp = commands.add_parser("serve-mock-mcp", help="Run the harmless synthetic MCP server on 127.0.0.1")
    mock_mcp.add_argument("--port", type=int, default=8765)
    run = commands.add_parser("run", help="Run the bounded baseline or dynamic suite")
    run.add_argument("--config", required=True)
    run.add_argument("--mode", choices=("baseline", "dynamic"), default="baseline")
    run.add_argument("--output-dir", default="reports")
    run.add_argument("--judge", action="store_true", help="Use the optional Groq semantic judge on ambiguous synthetic cases")
    export = commands.add_parser("promptfoo-config", help="Export cases to Promptfoo for the scoped HTTP target")
    export.add_argument("--config", required=True)
    export.add_argument("--output", default="promptfooconfig.yaml")
    promptfoo_run = commands.add_parser("run-promptfoo", help="Execute the static suite with Promptfoo and normalize its traces")
    promptfoo_run.add_argument("--config", required=True)
    promptfoo_run.add_argument("--output-dir", default="reports")
    promptfoo_run.add_argument("--executable", default="promptfoo")
    compare = commands.add_parser("compare", help="Compare two AgentShield JSON reports")
    compare.add_argument("before")
    compare.add_argument("after")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config_path = getattr(args, "config", None)
    env_search_directory = Path(config_path).expanduser().resolve().parent if config_path else None
    load_local_environment(env_search_directory)
    try:
        if args.command == "compare":
            print(json.dumps(compare_reports(args.before, args.after), indent=2))
            return 0
        if args.command == "serve-mock-mcp":
            if not 1 <= args.port <= 65535:
                raise AgentShieldError("--port must be in 1..65535.")
            serve_mock_mcp(args.port)
            return 0
        config = load_config(args.config)
        if args.command == "run" and args.judge:
            if config.data_classification not in {"synthetic", "redacted_synthetic"}:
                raise AgentShieldError("--judge requires project.data_classification: synthetic or redacted_synthetic.")
            if config.models.provider != "groq" or not config.models.judge_model:
                raise AgentShieldError("--judge requires models.provider: groq and models.judge_model.")
        if args.command == "validate-config":
            print(f"Configuration valid for project '{redact(config.name)}' ({config.environment}); target adapter: {config.target.adapter}.")
            return 0
        if args.command == "discover":
            if args.live:
                fixture = discover_remote_tools(config)
                source = config.mcp.server_url
            else:
                fixture = [{"name": "search_documents", "description": "Search synthetic test documents", "inputSchema": {"type": "object"}},
                           {"name": "transfer_funds", "description": "Transfer funds between accounts", "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}}}]
                source = config.target.fixture
            found = discover_tools(config, fixture, source=source)
            if args.previous:
                previous = [ToolMetadata(**record) for record in json.loads(Path(args.previous).read_text(encoding="utf-8"))]
                print(json.dumps(metadata_changes(previous, found), indent=2))
            records = [{"name": redact(t.name), "description": redact(t.description), "input_schema": redact(t.input_schema), "impact": t.impact, "authorized": t.authorized, "fingerprint": t.fingerprint} for t in found]
            rendered = json.dumps(records, indent=2)
            if args.output:
                destination = Path(args.output)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(rendered, encoding="utf-8")
                print(f"Wrote discovered metadata: {destination}")
            else:
                print(rendered)
            return 0
        if args.command == "invoke-mcp-tool":
            try:
                arguments = json.loads(args.arguments_json)
            except json.JSONDecodeError as exc:
                raise AgentShieldError("--arguments-json must contain valid JSON.") from exc
            record = invoke_remote_tool(config, args.tool, arguments)
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
            print(f"MCP invocation {record['decision']}: {record['tool_name']}. Redacted audit record: {destination}")
            return 1 if record["decision"] != "allowed" else 0
        if args.command == "promptfoo-config":
            path = write_promptfoo_config(load_baseline(config.testing.categories), args.output, config)
            print(f"Wrote Promptfoo configuration: {path}")
            return 0
        if args.command == "run-promptfoo":
            cases = load_baseline(config.testing.categories)[:config.testing.max_total_tests]
            if not cases:
                raise AgentShieldError("No baseline cases matched the configured Promptfoo run.")
            now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            project_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(redact(config.name))).strip("-_")[:64] or "agentshield"
            result = run_promptfoo(cases, config, run_id=f"{project_slug}-promptfoo-{now}", executable=args.executable)
            output = Path(args.output_dir)
            json_path = write_json_report(result, output / f"{result.run_id}.json")
            html_path = write_html_report(result, output / f"{result.run_id}.html")
            print(f"Completed {len(result.traces)} Promptfoo cases. Findings: {len(result.findings)}. Reports: {json_path}, {html_path}")
            return 1 if thresholds_violated(list(result.findings), config) else 0
        cases = load_baseline(config.testing.categories)
        budget = RunBudget(config)
        if args.mode == "dynamic":
            if config.models.provider != "groq":
                raise AgentShieldError("Dynamic mode requires models.provider: groq and a configured attack_model.")
            generated: list[AttackCase] = []
            remaining = max(0, config.testing.max_total_tests - len(cases))
            for category in config.testing.categories:
                count = min(config.testing.generated_variants_per_category, remaining)
                token_limit = min(config.models.max_tokens, budget.tokens_remaining)
                if count and token_limit:
                    variants = generate_variants(category, target_context="Synthetic isolated agent fixture; use synthetic examples only.", count=count, model=config.models.attack_model, max_tokens=token_limit, timeout=config.models.timeout_seconds, before_request=budget.before_request)
                    generated.extend(variants)
                    remaining -= len(variants)
            known = {" ".join(case.prompt.split()).casefold() for case in cases}
            for case in generated:
                normalized = " ".join(case.prompt.split()).casefold()
                if normalized not in known:
                    cases.append(case)
                    known.add(normalized)
        cases = cases[:config.testing.max_total_tests]
        if not cases:
            raise AgentShieldError("No cases matched the selected categories and test budget.")
        now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        project_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(redact(config.name))).strip("-_")[:64] or "agentshield"
        run_id = f"{project_slug}-{now}"
        adapter = _adapter(config)
        result = run_cases(cases, adapter, config, run_id=run_id, budget=budget)
        adaptive_rounds = 0
        seen = {" ".join(case.prompt.split()).casefold() for case in cases}
        if args.mode == "dynamic" and config.testing.adaptive_retries:
            for attempt in range(1, config.testing.adaptive_retries + 1):
                if budget.case_count >= config.testing.max_total_tests:
                    break
                # Confirmed policy violations stop adaptation. Only ambiguous cases
                # receive a bounded follow-up, summarized without target response text.
                if any(finding.outcome == "confirmed" for finding in result.findings):
                    break
                review_categories = list(dict.fromkeys(finding.category for finding in result.findings if finding.outcome == "needs_review"))
                if not review_categories:
                    break
                adaptive_cases: list[AttackCase] = []
                for category in review_categories:
                    if len(adaptive_cases) + budget.case_count >= config.testing.max_total_tests:
                        break
                    token_limit = min(config.models.max_tokens, budget.tokens_remaining)
                    if token_limit < 1:
                        break
                    variants = generate_variants(category, target_context="Redacted summary: the prior semantic result was ambiguous. Create one distinct synthetic follow-up within this category; include no target data.", count=1, model=config.models.attack_model, max_tokens=token_limit, timeout=config.models.timeout_seconds, before_request=budget.before_request)
                    for variant in variants:
                        normalized = " ".join(variant.prompt.split()).casefold()
                        if normalized in seen:
                            continue
                        seen.add(normalized)
                        adaptive_cases.append(replace(variant, case_id=f"adaptive-{attempt}-{variant.case_id}", prompt_version=f"groq-adaptive-v1-{attempt}"))
                if not adaptive_cases:
                    break
                follow_up = run_cases(adaptive_cases, adapter, config, run_id=run_id, budget=budget)
                adaptive_rounds += 1
                result = RunResult(run_id, result.traces + follow_up.traces, result.findings + follow_up.findings,
                                   {**follow_up.metadata, "case_count": budget.case_count, "total_case_count": budget.case_count, "request_count": budget.request_count, "adaptive_rounds": adaptive_rounds, "elapsed_seconds": round(budget.elapsed(), 3)})
        if not adaptive_rounds:
            result = RunResult(result.run_id, result.traces, result.findings, {**result.metadata, "adaptive_rounds": 0})
        if args.judge:
            trace_by_id = {str(trace["case_id"]): dict(trace) for trace in result.traces}
            review_ids = list(dict.fromkeys(finding.case_id for finding in result.findings if finding.outcome == "needs_review"))[:20]
            findings = list(result.findings)
            judge_calls = 0
            judge_failures = 0
            if not any(finding.outcome == "confirmed" for finding in findings):
                for case_id in review_ids:
                    trace = trace_by_id.get(case_id)
                    if not trace:
                        continue
                    token_limit = min(300, budget.tokens_remaining)
                    if token_limit < 1:
                        break
                    try:
                        verdict = judge_semantics(str(trace.get("prompt", "")), str(trace.get("response", "")), expected_policy=str(trace.get("expected_policy", "")), model=config.models.judge_model, timeout=config.models.timeout_seconds, max_tokens=token_limit, before_request=budget.before_request)
                        trace["judge"] = verdict
                        judge_calls += 1
                        if verdict["verdict"] == "violation":
                            findings.append(Finding(f"{case_id}-semantic-judge", case_id, str(trace.get("category", "")), "medium", "judge_assessed", "Semantic policy violation assessed", verdict["rationale"], ("trace.judge", "trace.response")))
                        elif verdict["verdict"] == "no_violation":
                            findings = [finding for finding in findings if not (finding.case_id == case_id and finding.outcome == "needs_review")]
                            findings.append(Finding(f"{case_id}-semantic-judge", case_id, str(trace.get("category", "")), "informational", "judge_assessed", "No semantic violation assessed", verdict["rationale"], ("trace.judge", "trace.response")))
                    except ProviderError:
                        trace["judge"] = {"outcome": "needs_review", "verdict": "unavailable", "rationale": "The semantic judge request failed; human review is required."}
                        judge_failures += 1
            result = RunResult(result.run_id, tuple(trace_by_id.get(str(trace["case_id"]), trace) for trace in result.traces), tuple(findings),
                               {**result.metadata, "judge_cases": judge_calls, "judge_failures": judge_failures, "request_count": budget.request_count, "tokens_reserved": budget.tokens_reserved, "elapsed_seconds": round(budget.elapsed(), 3)})
        output = Path(args.output_dir)
        json_path = write_json_report(result, output / f"{result.run_id}.json")
        html_path = write_html_report(result, output / f"{result.run_id}.html")
        print(f"Completed {result.metadata.get('total_case_count', len(cases))} cases. Findings: {len(result.findings)}. Reports: {json_path}, {html_path}")
        if args.judge:
            print(f"Semantic judge: {result.metadata.get('judge_cases', 0)} assessed, {result.metadata.get('judge_failures', 0)} provider failures.")
        return 1 if thresholds_violated(list(result.findings), config) else 0
    except (AgentShieldError, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        print(f"agentshield: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
