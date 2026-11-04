"""Validated request and response models for the local web API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentshield.taxonomy import ATTACK_CATEGORIES


ProfileName = Literal["finance-mock", "rag-mock", "mcp-mock"]


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: ProfileName = "finance-mock"
    categories: list[str] | None = Field(default=None, min_length=1, max_length=10)
    max_cases: int = Field(default=10, ge=1, le=40)

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and (set(value) - ATTACK_CATEGORIES or len(value) != len(set(value))):
            raise ValueError("categories contains an unsupported or duplicate attack category")
        return value


class RunSummary(BaseModel):
    id: str
    profile: ProfileName
    status: Literal["queued", "running", "completed", "failed"]
    progress: int
    total_cases: int
    findings_count: int
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ProfileInfo(BaseModel):
    id: ProfileName
    name: str
    description: str
    categories: list[str]
