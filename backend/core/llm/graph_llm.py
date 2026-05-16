from __future__ import annotations

import httpx

from core.attack_path.remediation import ranked_remediations
from core.config import settings
from core.graph_engine import graph
from core.llm.prompt_builder import build_graph_prompt
from core.llm.validator import validate_answer

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def graph_context(question: str) -> dict:
    lowered = question.lower()
    context = {"attack_paths": graph.attack_paths(limit=10)}
    if "patch" in lowered or "fix" in lowered or "remediation" in lowered:
        context["remediations"] = ranked_remediations(limit=5)
    if "graph" in lowered or "show" in lowered:
        context["snapshot"] = graph.graph_snapshot()
    return context


def deterministic_answer(question: str, context: dict) -> str:
    remediations = context.get("remediations") or ranked_remediations(limit=3)
    if "patch" in question.lower() or "fix" in question.lower():
        if not remediations:
            return "The graph does not contain enough vulnerable package evidence to recommend patches yet."
        lines = ["Based on the graph, patch these packages first:"]
        for idx, item in enumerate(remediations[:3], start=1):
            lines.append(
                f"{idx}. Update {item['package_name']} from {item['current_version']} to {item['fixed_version']} "
                f"to reduce risk across {len(item['services'])} service(s): {', '.join(item['services'])}."
            )
        return "\n".join(lines)
    paths = context.get("attack_paths", [])
    if not paths:
        return "The graph does not contain attack paths to business data yet."
    top = paths[0]
    return (
        f"The biggest attack path is {top['cve_id']} through {top['package_name']} into "
        f"{top['service_name']}, reaching {top['data_name']} in {top['hops']} hops. "
        f"The graph risk score is {top['risk_score']}/10."
    )


async def answer_question(question: str) -> dict:
    context = graph_context(question)
    if not settings.groq_api_key:
        answer = deterministic_answer(question, context)
        return {"answer": answer, "context": context, "validation": validate_answer(answer, context), "model": "deterministic-local"}
    messages = build_graph_prompt(question, context)
    headers = {"Authorization": f"Bearer {settings.groq_api_key}", "Content-Type": "application/json"}
    payload = {"model": "llama-3.1-8b-instant", "messages": messages, "temperature": 0.1}
    async with httpx.AsyncClient(timeout=45) as client:
        response = await client.post(GROQ_URL, headers=headers, json=payload)
        response.raise_for_status()
    answer = response.json()["choices"][0]["message"]["content"]
    validation = validate_answer(answer, context)
    if not validation["valid"]:
        answer = deterministic_answer(question, context)
        validation = validate_answer(answer, context)
    return {"answer": answer, "context": context, "validation": validation, "model": "llama-3.1-8b-instant"}
