from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core.llm.graph_llm import answer_question

router = APIRouter()


class QueryRequest(BaseModel):
    question: str = Field(..., examples=["Which 3 patches give me the biggest risk reduction?"])
    # Optional scope hint supplied by the frontend when the user is viewing a
    # specific scan/repo. The backend uses this only as a fallback — the
    # question text takes priority if it mentions a known service. Both fields
    # are optional so existing clients sending only ``question`` continue to
    # work unchanged.
    service: str | None = Field(default=None, examples=["juice-shop"])
    repo_url: str | None = Field(default=None, examples=["https://github.com/juice-shop/juice-shop"])


@router.post("/query")
async def query(request: QueryRequest):
    # Derive a service-name hint from either explicit ``service`` or the tail
    # of a github repo URL (e.g. ``.../juice-shop/juice-shop`` → ``juice-shop``).
    hint = request.service
    if not hint and request.repo_url:
        tail = request.repo_url.rstrip("/").split("/")[-1]
        hint = tail or None
    return await answer_question(request.question, service_hint=hint)
