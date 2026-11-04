"""SQLite persistence for run metadata and redacted report JSON."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                total_cases INTEGER NOT NULL,
                findings_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                report_json TEXT
            )""")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def create(self, run_id: str, profile: str, total_cases: int) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO runs(id,profile,status,total_cases,created_at) VALUES(?,?,?,?,?)",
                               (run_id, profile, "queued", total_cases, utc_now()))

    def delete(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM runs WHERE id=?", (run_id,))

    def update(self, run_id: str, **values: Any) -> None:
        allowed = {"status", "progress", "findings_count", "started_at", "completed_at", "error", "report_json", "total_cases"}
        if not values or set(values) - allowed:
            raise ValueError("Unsupported run update fields")
        assignments = ",".join(f"{key}=?" for key in values)
        with self._connect() as connection:
            connection.execute(f"UPDATE runs SET {assignments} WHERE id=?", (*values.values(), run_id))

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def recover_interrupted(self) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE runs SET status='failed', error='Run interrupted by API restart', completed_at=? WHERE status IN ('queued','running')", (utc_now(),))
