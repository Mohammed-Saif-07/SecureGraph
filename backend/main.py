import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from api.middleware import RateLimitAndAuthMiddleware
from api.routes import auth, graph, llm, reports, scans
from core.config import settings
from core.graph_engine import graph as graph_engine
from core.ingestion.nvd_fetcher import import_recent_cves
from core.sql_db import SessionLocal, init_db

logger = logging.getLogger(__name__)


def _cve_count() -> int:
    rows = graph_engine.execute("MATCH (c:CVE) RETURN count(c) AS count")
    return int(rows[0]["count"]) if rows else 0


async def _auto_import_nvd_if_needed() -> None:
    try:
        if not settings.auto_import_nvd:
            return
        if _cve_count() >= settings.nvd_import_min_cves:
            return
        result = await import_recent_cves(months=settings.nvd_import_months, max_pages=settings.nvd_import_max_pages)
        logger.info("NVD startup import completed: %s", result)
    except Exception:
        logger.exception("NVD startup import failed")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
    except Exception:
        logger.exception("PostgreSQL startup initialization failed")

    try:
        graph_engine.setup_schema()
        graph_engine.seed_demo_graph()
        graph_engine.refresh_predictions(limit=5000)
        asyncio.create_task(_auto_import_nvd_if_needed())
    except Exception:
        logger.exception("Neo4j startup initialization failed")

    yield
    graph_engine.close()

app = FastAPI(
    title="SecureGraph",
    description="AI-powered vulnerability intelligence and attack path graph platform.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitAndAuthMiddleware)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(llm.router, prefix="/api/llm", tags=["llm"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

@app.get("/health")
def health():
    neo4j_ok = False
    postgres_ok = False
    try:
        graph_engine.execute("RETURN 1 AS ok")
        neo4j_ok = True
    except Exception:
        neo4j_ok = False
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        postgres_ok = True
    except Exception:
        postgres_ok = False
    return {"status": "ok" if neo4j_ok and postgres_ok else "degraded", "neo4j": neo4j_ok, "postgres": postgres_ok}
