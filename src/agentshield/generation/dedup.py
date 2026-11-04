"""Normalized payload deduplication helpers."""

from __future__ import annotations

import re
from collections.abc import Iterable


def normalize_payload(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def deduplicate_payloads(payloads: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for payload in payloads:
        normalized = normalize_payload(payload)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(payload.strip())
    return unique
