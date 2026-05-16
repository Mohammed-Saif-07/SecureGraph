from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import auth, graph, llm, reports, scans
from core.config import settings
from core.graph_engine import graph as graph_engine
from core.sql_db import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    graph_engine.setup_schema()
    graph_engine.seed_demo_graph()
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

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(llm.router, prefix="/api/llm", tags=["llm"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

@app.get("/health")
def health():
    return {"status": "ok", "service": "securegraph"}
