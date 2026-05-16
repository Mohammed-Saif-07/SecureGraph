from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from core.llm.graph_llm import answer_question

router = APIRouter()


class QueryRequest(BaseModel):
    question: str


@router.post("/query")
async def query(request: QueryRequest):
    return await answer_question(request.question)
