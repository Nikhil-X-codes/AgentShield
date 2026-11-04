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

Responsibilities are separated by package: `config` validates inputs and scope; `adapters` defines target interfaces; `discovery` inspects fixture metadata; `generation` owns taxonomy cases and optional Groq generation; `execution` bounds requests and captures traces; `evaluation` applies deterministic checks and provides an optional judge helper; `reporting` writes reports and comparisons; `cli` exposes workflows.

The adapter boundary lets a RAG or MCP-connected agent's isolated HTTP harness supply responses and observed traces without coupling generators or reports to a specific provider. A separate read-only Streamable HTTP MCP client discovers tool metadata. Tool discovery is informational. Only explicit scope configuration can authorize a tool.
