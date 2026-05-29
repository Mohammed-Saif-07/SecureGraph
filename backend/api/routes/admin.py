from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from core.graph_engine import graph
from core.ingestion.nvd_fetcher import import_recent_cves

router = APIRouter()

_import_task: asyncio.Task | None = None
_import_status: dict[str, Any] = {
    "state": "idle",
    "started_at": None,
    "finished_at": None,
    "result": None,
    "error": None,
}


def _require_admin_token(x_admin_token: str | None) -> None:
    expected = settings.import_admin_token or settings.jwt_secret
    if not expected or x_admin_token != expected:
        raise HTTPException(status_code=401, detail="Invalid admin token")


async def _run_import(months: int, max_pages: int | None) -> None:
    global _import_status
    _import_status = {
        "state": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "result": None,
        "error": None,
    }
    try:
        result = await import_recent_cves(months=months, max_pages=max_pages)
        summary = graph.cve_summary(sample_limit=5)
        _import_status = {
            **_import_status,
            "state": "completed",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "result": {**result, "summary": summary},
        }
    except Exception as exc:  # pragma: no cover - defensive status reporting
        _import_status = {
            **_import_status,
            "state": "failed",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": f"{type(exc).__name__}: {exc}",
        }


@router.post("/nvd/import")
async def start_nvd_import(
    months: int | None = None,
    max_pages: int | None = None,
    x_admin_token: str | None = Header(default=None),
):
    _require_admin_token(x_admin_token)
    global _import_task
    if _import_task and not _import_task.done():
        return {"status": "already_running", **_import_status}

    import_months = months or settings.nvd_import_months
    import_max_pages = settings.nvd_import_max_pages if max_pages is None else max_pages
    _import_task = asyncio.create_task(_run_import(import_months, import_max_pages))
    return {"status": "started", "months": import_months, "max_pages": import_max_pages}


@router.get("/nvd/import/status")
def nvd_import_status(x_admin_token: str | None = Header(default=None)):
    _require_admin_token(x_admin_token)
    return _import_status
