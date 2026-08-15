"""Issue/error records, date normalisation, name and revision classification."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._constants import BRANCH_LIKE, COMMIT_SHA_RE, SHORT_SHA_RE


def _issue(
    issue_type: str,
    severity: str,
    detail: str,
    evidence: Any = None,
    recommendation: str | None = None,
) -> dict:
    return {
        "type": issue_type,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _error(
    source: str,
    code: str,
    detail: str,
    retryable: bool = False,
) -> dict:
    return {
        "source": source,
        "code": code,
        "detail": detail,
        "retryable": retryable,
    }


def _normalize_date(value: str | None) -> str | None:
    """Normalize ISO timestamps to YYYY-MM-DD when possible."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt.date().isoformat()
    except ValueError:
        if re.match(r"^\d{4}-\d{2}-\d{2}", text):
            return text[:10]
        return None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _days_since(iso_date: str | None, now: datetime | None = None) -> int | None:
    dt = _parse_datetime(iso_date)
    if dt is None:
        # try YYYY-MM-DD
        if iso_date and re.match(r"^\d{4}-\d{2}-\d{2}$", iso_date):
            dt = datetime.fromisoformat(iso_date).replace(tzinfo=timezone.utc)
        else:
            return None
    ref = now or datetime.now(timezone.utc)
    return max(0, (ref - dt).days)


def _safe_path_for_log(path: str | Path) -> str:
    """Avoid leaking home-directory paths in logs."""
    name = Path(path).name
    return name or "<path>"


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_commit_sha(value: str | None) -> bool:
    return bool(value and COMMIT_SHA_RE.fullmatch(value))


def _classify_revision(value: str | None) -> tuple[str | None, bool]:
    """Return (revision_type, revision_pinned)."""
    if not value:
        return None, False
    if _is_commit_sha(value):
        return "commit", True
    if value.lower() in BRANCH_LIKE or "/" in value:
        return "branch", False
    if re.match(r"^v?\d+\.\d+", value, re.IGNORECASE):
        return "tag", False
    if SHORT_SHA_RE.fullmatch(value):
        return "short_sha", False
    return "ref", False
