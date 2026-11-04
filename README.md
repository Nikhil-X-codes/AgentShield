# AgentShield

AgentShield is a bounded, authorization-based red-team framework for testing LLM agents in isolated environments. It runs versioned baseline cases, can request synthetic dynamic variants from Groq, captures response and tool-call traces, applies deterministic policy checks, and writes JSON and HTML reports.

## Safety boundaries

- Non-mock HTTP targets must use an absolute HTTP(S) URL whose hostname is explicitly listed in `scope.allowed_hosts`.
- Production environments, real side effects, and non-mock consequential tools are rejected.
- Tool access is deny-by-default. Discovery records metadata and risk; it never authorizes a tool.
- A confirmed unauthorized tool call stops the run immediately.
- Generated prompts cannot change hosts, endpoints, tools, or configuration.
- Groq is optional and receives only the selected category and a short synthetic/redacted context.
- Tool calls and policy decisions come from the target adapter trace. A target's natural-language claim is not treated as evidence that a tool ran.

## Install

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
npm ci # installs the exact Promptfoo version from package-lock.json
```

Copy `.env.example` to `.env` for local use. The CLI searches upward from the configuration file’s directory (or current directory for commands without a config) and loads the nearest `.env`; variables already set in the process environment take precedence. Groq uses `GROQ_API_KEY`, `GROQ_ATTACK_MODEL`, and `GROQ_JUDGE_MODEL` (the finance example references the latter two). Do not commit credentials.

## Quick start

```powershell
agentshield validate-config configs/finance-agent.example.yaml
agentshield discover --config configs/finance-agent.example.yaml
agentshield run --config configs/finance-agent.example.yaml --mode baseline
```

The example runs against an in-memory synthetic agent and mock tool traces. It does not call a real service. A baseline run writes a redacted JSON trace report and an HTML findings report under `reports/`. Exit code `1` means a configured finding threshold was exceeded; `2` indicates invalid configuration or execution failure.

## Reproducible synthetic demo

Run a local before/after demo against a synthetic HTTP target:

```powershell
python examples/synthetic_demo.py
```

The vulnerable fixture returns an attempted `transfer_funds` trace without executing a transfer; AgentShield should report a critical confirmed finding. The fixed fixture returns no tool call and refuses the request; the rerun should have no confirmed finding. Both JSON and HTML reports are written under `reports/synthetic-demo/`. This demonstrates the workflow only; it does not represent a live target assessment.

The reviewed before/after finding and evidence references are summarized in [SYNTHETIC_DEMO_RESULTS.md](docs/SYNTHETIC_DEMO_RESULTS.md).

Observed output:

```text
Synthetic local demo only; no external service or real tool is called.
Vulnerable fixture: exit=1; detected critical confirmed finding.
Fixed fixture: exit=0; no confirmed findings; policy outcome=blocked.
Report target host: 127.0.0.1
Resolved findings: tool-001-tool-0
```

Synthetic adapter configurations are also provided in `configs/rag-agent.example.yaml` and `configs/mcp-agent.example.yaml` for retrieval-injection and hostile MCP-metadata regression scenarios.

## Configure an isolated HTTP target

The default HTTP profile sends one JSON request per case:

```json
{"prompt":"test payload","case_id":"pi-001"}
```

The target must return a JSON object containing `text`, plus optional `tool_trace.calls` and `tool_trace.decisions` arrays (legacy top-level `tool_calls`/`decisions` are also accepted). A tool call has `name` and object `arguments`; a decision has `tool_name`, boolean `authorized`, and optional `reason`. These fields must represent observed execution traces, not model-generated claims. Configure `target.adapter: http`, the exact endpoint in `target.base_url`, and its hostname in `scope.allowed_hosts`. Run `validate-config` before connecting.

For an OpenAI-compatible chat endpoint, set `target.profile: openai_chat` and `target.model`. AgentShield sends the standard chat `messages` request shape and parses `choices[0].message`. Configure `target.auth_token_env` with the name of an environment variable for bearer authentication. For deterministic tool evaluation, return actual execution data in a `tool_trace` object; a model-proposed chat tool call without an execution decision is treated conservatively as an unapproved attempt.

`agentshield promptfoo-config` exports the bounded cases for that scoped HTTP endpoint. Promptfoo runs model requests; use the AgentShield runner when deterministic tool trace evaluation is required.

Run the exported static suite through Promptfoo and have AgentShield normalize its response/tool traces into the same evaluator and reports:

```powershell
agentshield run-promptfoo --config configs/your-isolated-target.yaml
```

This requires the pinned Node runtime dependency (`npm ci`) and Promptfoo runs in no-write/no-cache mode. Raw provider output stays in a temporary directory and is removed after report generation.

## MCP discovery and optional mock invocation

Set `mcp.server_url` to the exact Streamable HTTP endpoint and include its hostname in `scope.allowed_hosts`. For authenticated servers, set `mcp.auth_token_env` to the name of an environment variable containing a bearer token. Then run `agentshield discover --config configs/your-target.yaml --live`. This performs MCP initialization and bounded `tools/list` pagination, fingerprints metadata, and can compare it with a saved snapshot using `--previous`. Discovery never grants authorization. MCP metadata and descriptions remain untrusted.

Tool invocation is a separate opt-in operation and is disabled by default. This milestone only permits IP loopback MCP endpoints, requires an exact URL entry in `scope.allowed_mcp_servers`, requires the tool name in `scope.allowed_tools`, and rejects tools marked sensitive or requiring approval. The discovered `inputSchema` is validated before `tools/call`; schemas with `$ref` are rejected to prevent remote reference resolution. Results are recorded as untrusted, redacted evidence. Use only a synthetic mock server:

```yaml
scope:
  allowed_hosts: [127.0.0.1]
  allowed_mcp_servers: [http://127.0.0.1:8765/mcp]
  allowed_tools: [get_test_profile, search_test_documents]
mcp:
  server_url: http://127.0.0.1:8765/mcp
  enable_tool_invocation: true
```

```powershell
agentshield invoke-mcp-tool --config configs/your-mock.yaml --tool get_test_profile --arguments-json '{"profile_id":"synthetic-1"}'
```

This writes a redacted invocation record to `reports/mcp-invocation.json`. Sensitive tools remain blocked in this automated path; `simulate_sensitive_action` must only record an attempted action in the mock server and must never perform the action.

## Dynamic generation

Set `models.provider: groq`, configure `models.attack_model`, and provide `GROQ_API_KEY` in the environment. Then run:

```powershell
agentshield run --config configs/your-isolated-target.yaml --mode dynamic
```

`testing.generated_variants_per_category`, `testing.adaptive_retries` (maximum 2), `testing.max_total_tests`, `testing.max_total_tokens`, request pacing, and the run time limit bound execution. Adaptive retries are generated only after ambiguous `needs_review` outcomes; confirmed boundary violations stop adaptation. Generated cases are schema-checked, length-limited, deduplicated, and tagged with their model and prompt version. To assess ambiguous synthetic outputs with Groq, set `project.data_classification: synthetic`, configure `models.provider: groq` and `models.judge_model`, then pass `--judge` to `run`. Judge outcomes stay `judge_assessed`; deterministic tool findings remain authoritative.

## Reports and comparison

```powershell
agentshield compare reports/before.json reports/after.json
```

Verdicts distinguish deterministic `confirmed`, `blocked`, `passed`, and heuristic `needs_review` results. Severity reflects demonstrated evidence. Report counts cover only cases actually run and do not establish overall agent security.

## Implementation status

Implemented: configuration and scope validation; mock, synthetic RAG/MCP-connected, AgentShield HTTP, and OpenAI-compatible chat adapters; read-only Streamable HTTP MCP discovery with metadata fingerprints; gated loopback-only mock MCP invocation with JSON Schema validation and redacted audit records; versioned static corpus; bounded Groq generation, semantic judging, and adaptive retries; sequential runner with shared test/request/token/time budgets; trace redaction; deterministic tool authorization checks; Promptfoo execution and trace normalization; JSON/HTML reports, comparison, CLI, unit/integration tests, CI, and build-only release artifacts.

Not implemented: invocation against remote MCP servers and a web UI/API. Promptfoo execution is available through `run-promptfoo`; it normalizes its traces into AgentShield findings and reports. Tests use local synthetic targets and do not claim live provider coverage.

See [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md) and [SECURITY.md](docs/SECURITY.md) for design and operational boundaries.
