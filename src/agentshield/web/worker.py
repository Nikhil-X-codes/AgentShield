"""Single bounded background worker that runs only registered mock profiles."""

from __future__ import annotations

import json
import logging
import queue
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentshield.adapters.fixtures import MCPConnectedMockAdapter, RAGMockAdapter
from agentshield.adapters.mock import MockAgentAdapter
from agentshield.config import load_config
from agentshield.errors import AgentShieldError
from agentshield.execution.runner import RunBudget, RunResult, run_cases
from agentshield.generation.corpus import load_baseline
from agentshield.reporting.reports import report_data

from .schemas import ProfileName
from .storage import RunStore, utc_now

_LOGGER = logging.getLogger("agentshield.web.worker")
_PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
_PROFILES: dict[str, tuple[str, str, str]] = {
    "finance-mock": ("Finance safety mock", "Synthetic tool policy checks.", "finance-mock.yaml"),
    "rag-mock": ("RAG injection mock", "Synthetic retrieval injection checks.", "rag-mock.yaml"),
    "mcp-mock": ("MCP metadata mock", "Synthetic MCP tool policy checks; no network MCP calls.", "mcp-mock.yaml"),
}


def profile_catalog() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for profile_id, (name, description, relative_path) in _PROFILES.items():
        config = load_config(_PROFILE_DIR / relative_path)
        records.append({"id": profile_id, "name": name, "description": description,
                        "categories": list(config.testing.categories)})
    return records


class RunWorker:
    def __init__(self, store: RunStore, *, queue_size: int = 8) -> None:
        self.store = store
        self._queue: queue.Queue[tuple[str, ProfileName, tuple[str, ...], int] | None] = queue.Queue(maxsize=queue_size)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.store.recover_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(target=self._work, name="agentshield-web-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread:
            self._thread.join(timeout=5)

    def submit(self, run_id: str, profile: ProfileName, categories: tuple[str, ...], max_cases: int) -> bool:
        try:
            self._queue.put_nowait((run_id, profile, categories, max_cases))
            return True
        except queue.Full:
            return False

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if job is None:
                self._queue.task_done()
                break
            run_id, profile, categories, max_cases = job
            try:
                self._execute(run_id, profile, categories, max_cases)
            except Exception:
                _LOGGER.exception("Assessment run %s failed", run_id)
                self.store.update(run_id, status="failed", error="Assessment failed; inspect server logs.", completed_at=utc_now())
            finally:
                self._queue.task_done()

    def _execute(self, run_id: str, profile: ProfileName, categories: tuple[str, ...], max_cases: int) -> None:
        _name, _description, relative_path = _PROFILES[profile]
        config_path = (_PROFILE_DIR / relative_path).resolve()
        if _PROFILE_DIR.resolve() not in config_path.parents:
            raise AgentShieldError("Registered profile path is outside the profile directory.")
        config = load_config(config_path)
        if config.target.adapter not in {"mock", "mock_rag", "mock_mcp"}:
            raise AgentShieldError("Web runs are restricted to bundled mock adapters.")
        selected_categories = categories or tuple(config.testing.categories)
        adjusted_testing = replace(config.testing, categories=selected_categories,
                                   max_total_tests=min(max_cases, config.testing.max_total_tests),
                                   generated_variants_per_category=0, adaptive_retries=0)
        config = replace(config, testing=adjusted_testing)
        config.validate()
        cases = load_baseline(config.testing.categories)[:config.testing.max_total_tests]
        if not cases:
            raise AgentShieldError("No baseline cases match the selected categories.")
        adapter = {"mock": MockAgentAdapter, "mock_rag": RAGMockAdapter, "mock_mcp": MCPConnectedMockAdapter}[config.target.adapter](config)
        started = utc_now()
        self.store.update(run_id, status="running", started_at=started, total_cases=len(cases), progress=0)

        def on_progress(done: int, total: int) -> None:
            self.store.update(run_id, progress=min(99, int(done * 100 / max(total, 1))))

        result: RunResult = run_cases(cases, adapter, config, run_id=run_id, budget=RunBudget(config), progress_callback=on_progress)
        data = report_data(result)
        self.store.update(run_id, status="completed", progress=100, findings_count=len(result.findings),
                          report_json=json.dumps(data, ensure_ascii=False), completed_at=utc_now())
