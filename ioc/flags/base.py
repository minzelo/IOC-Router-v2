"""Shared helpers and flag builder for all per-provider flag extractors."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _flag(
    id: str,
    label: str,
    threat_type: str,
    severity: str,
    mitre: list[str],
    detail: str,
    source: str,
) -> dict:
    return {
        "id": id,
        "label": label,
        "threat_type": threat_type,
        "severity": severity,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "mitre": mitre,
        "detail": detail,
        "source": source,
    }


def _days_since(ts: Any) -> int | None:
    """Convert unix timestamp or ISO string to age in days. None if unparseable."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            return (datetime.now(tz=timezone.utc) - dt).days
        except Exception:
            return None
    if isinstance(ts, str):
        raw = ts.strip().rstrip("Z")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(raw[:len(fmt)+2], fmt).replace(tzinfo=timezone.utc)
                return (datetime.now(tz=timezone.utc) - dt).days
            except Exception:
                continue
    return None


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default
