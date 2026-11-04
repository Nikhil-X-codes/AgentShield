"""JSON/HTML reports and before/after comparisons."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from agentshield.execution.runner import RunResult
from agentshield.execution.runner import redact


def report_data(result: RunResult) -> dict[str, Any]:
    return redact({"run_id": result.run_id, "metadata": result.metadata, "traces": list(result.traces), "findings": [asdict(finding) for finding in result.findings]})


def write_json_report(result: RunResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_data(result), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_html_report(result: RunResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(f"<tr><td>{html.escape(f.case_id)}</td><td>{html.escape(f.severity)}</td><td>{html.escape(f.outcome)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.rationale)}</td></tr>" for f in result.findings)
    page = "<!doctype html><meta charset='utf-8'><title>AgentShield report</title><h1>AgentShield run " + html.escape(result.run_id) + "</h1><p>Cases: " + str(result.metadata.get("case_count", 0)) + "</p><table><thead><tr><th>Case</th><th>Severity</th><th>Outcome</th><th>Finding</th><th>Rationale</th></tr></thead><tbody>" + rows + "</tbody></table>"
    path.write_text(page, encoding="utf-8")
    return path


def compare_reports(before_path: str | Path, after_path: str | Path) -> dict[str, object]:
    before = json.loads(Path(before_path).read_text(encoding="utf-8"))
    after = json.loads(Path(after_path).read_text(encoding="utf-8"))
    before_findings = {item["finding_id"]: item for item in before.get("findings", [])}
    after_findings = {item["finding_id"]: item for item in after.get("findings", [])}
    return {"before_run": before.get("run_id"), "after_run": after.get("run_id"),
            "resolved": sorted(set(before_findings) - set(after_findings)),
            "new": sorted(set(after_findings) - set(before_findings)),
            "unchanged": sorted(set(before_findings) & set(after_findings))}
