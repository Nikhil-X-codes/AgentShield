from __future__ import annotations

import time

from fastapi.testclient import TestClient

from agentshield.web.api import create_app


def test_web_api_lists_registered_profiles_and_runs_synthetic_assessment(tmp_path):
    app = create_app(tmp_path / "web.sqlite3")
    with TestClient(app) as client:
        profiles = client.get("/api/profiles")
        assert profiles.status_code == 200
        assert {item["id"] for item in profiles.json()} == {"finance-mock", "rag-mock", "mcp-mock"}

        accepted = client.post("/api/runs", json={"profile": "rag-mock", "categories": ["rag_poisoning"], "max_cases": 1})
        assert accepted.status_code == 202
        run_id = accepted.json()["id"]
        deadline = time.monotonic() + 5
        state = accepted.json()
        while state["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
            time.sleep(0.02)
            state = client.get(f"/api/runs/{run_id}").json()
        assert state["status"] == "completed"
        assert state["progress"] == 100
        assert state["total_cases"] == 1
        report = client.get(f"/api/runs/{run_id}/report")
        assert report.status_code == 200
        assert report.json()["run_id"] == run_id
        assert report.json()["traces"]


def test_web_api_rejects_unregistered_targets_shell_fields_and_bad_categories(tmp_path):
    app = create_app(tmp_path / "web.sqlite3")
    with TestClient(app) as client:
        assert client.get("/api/health", headers={"host": "untrusted.example"}).status_code == 403
        assert client.post("/api/runs", json={"profile": "http-target", "target_url": "https://example.com"}).status_code == 422
        assert client.post("/api/runs", json={"profile": "finance-mock", "command": "python -c pass"}).status_code == 422
        assert client.post("/api/runs", json={"profile": "finance-mock", "categories": ["made_up"]}).status_code == 422
        assert client.get("/api/runs/not-a-uuid").status_code == 404
