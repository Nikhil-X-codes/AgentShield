# Architecture

```text
CLI -> configuration + immutable scope -> adapter -> bounded runner -> trace
                                             |                    |
                              mock / HTTP target            deterministic evaluator
                                                                   |
      static corpus / optional Groq generator ----------------> report
      MCP fixture or Streamable HTTP discovery -> impact classification/fingerprint
      Promptfoo exporter -> scoped HTTP test configuration
```

The optional web console is an additional local-only entry point:

```text
React/Vite (web-ui/) -> FastAPI routes + request schemas
                              |-> registered mock-profile service
                              |-> bounded single-worker queue -> existing adapters + runner
                              `-> SQLite run metadata and redacted report JSON
```

Responsibilities are separated by package: `config` validates inputs and scope; `adapters` defines target interfaces; `discovery` inspects fixture metadata; `generation` owns taxonomy cases and optional Groq generation; `execution` bounds requests and captures traces; `evaluation` applies deterministic checks and provides an optional judge helper; `reporting` writes reports and comparisons; `cli` exposes workflows.

The adapter boundary lets a RAG or MCP-connected agent's isolated HTTP harness supply responses and observed traces without coupling generators or reports to a specific provider. A separate read-only Streamable HTTP MCP client discovers tool metadata. Tool discovery is informational. Only explicit scope configuration can authorize a tool.

`agentshield.web.api` exposes only three registered synthetic profiles. The request schema rejects extra fields and cannot carry shell commands, target URLs, or filesystem paths. A single bounded worker invokes AgentShield's Python API in-process; no shell runner is exposed. The API and Vite dev server bind to loopback, and the API also rejects non-loopback peers and unexpected Host values. SQLite stores run states and the existing redacted report structure. This MVP has no user authentication and must not be exposed outside the local development machine.
