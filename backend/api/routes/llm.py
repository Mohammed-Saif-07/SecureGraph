from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core.llm.graph_llm import answer_question

router = APIRouter()


class QueryRequest(BaseModel):
    question: str = Field(..., examples=["Which 3 patches give me the biggest risk reduction?"])


@router.post("/query")
async def query(request: QueryRequest):
    return await answer_question(request.question)
