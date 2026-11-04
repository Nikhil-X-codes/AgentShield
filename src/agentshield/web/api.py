"""Loopback-only FastAPI app for registered synthetic AgentShield profiles."""

from __future__ import annotations

import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agentshield.generation.corpus import load_baseline

from .schemas import ProfileInfo, RunCreate, RunSummary
from .storage import RunStore
from .worker import RunWorker, profile_catalog



def create_app(database_path: str | Path | None = None, *, queue_size: int = 8) -> FastAPI:
    db_path = Path(database_path or os.environ.get("AGENTSHIELD_WEB_DB", Path.cwd() / "reports" / "agentshield-web.sqlite3"))
    store = RunStore(db_path)
    worker = RunWorker(store, queue_size=queue_size)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        worker.start()
        try:
            yield
        finally:
            worker.stop()

    app = FastAPI(title="AgentShield Local API", version="0.1.0", lifespan=lifespan)
    app.state.run_store = store
    app.state.run_worker = worker
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        peer = request.client.host if request.client else ""
        request_host = request.url.hostname or ""
        if peer not in {"127.0.0.1", "::1", "testclient"} or request_host not in {"127.0.0.1", "localhost", "testserver", "testclient"}:
            return JSONResponse(status_code=403, content={"detail": "The local AgentShield API accepts loopback clients only."})
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "agentshield-local-api"}

    @app.get("/api/profiles", response_model=list[ProfileInfo])
    def profiles() -> list[dict[str, Any]]:
        return profile_catalog()

    @app.post("/api/runs", response_model=RunSummary, status_code=status.HTTP_202_ACCEPTED)
    def create_run(body: RunCreate) -> dict[str, Any]:
        profile = next((item for item in profile_catalog() if item["id"] == body.profile), None)
        if profile is None:
            raise HTTPException(status_code=422, detail="Unknown registered profile.")
        selected_categories = tuple(body.categories or profile["categories"])
        eligible_count = len(load_baseline(selected_categories))
        total_cases = min(body.max_cases, eligible_count)
        if total_cases < 1:
            raise HTTPException(status_code=422, detail="No baseline cases match the selected categories.")
        run_id = str(uuid.uuid4())
        store.create(run_id, body.profile, total_cases)
        if not worker.submit(run_id, body.profile, selected_categories, body.max_cases):
            store.delete(run_id)
            raise HTTPException(status_code=503, detail="Assessment queue is full; retry when a run finishes.")
        record = store.get(run_id)
        assert record is not None
        return record

    @app.get("/api/runs", response_model=list[RunSummary])
    def list_runs() -> list[dict[str, Any]]:
        return store.list(limit=50)

    def get_run_or_404(run_id: str) -> dict[str, Any]:
        try:
            normalized = str(uuid.UUID(run_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Assessment run not found.") from exc
        record = store.get(normalized)
        if record is None:
            raise HTTPException(status_code=404, detail="Assessment run not found.")
        return record

    @app.get("/api/runs/{run_id}", response_model=RunSummary)
    def get_run(run_id: str) -> dict[str, Any]:
        return get_run_or_404(run_id)

    @app.get("/api/runs/{run_id}/report")
    def get_report(run_id: str) -> JSONResponse:
        record = get_run_or_404(run_id)
        if record["status"] != "completed" or not record["report_json"]:
            raise HTTPException(status_code=409, detail="The assessment report is not ready yet.")
        return JSONResponse(content=json.loads(record["report_json"]))

    return app


app = create_app()
