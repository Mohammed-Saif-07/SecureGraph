from __future__ import annotations
import json
import httpx
from core.attack_path.remediation import ranked_remediations
from core.config import settings
from core.graph_engine import graph
from core.llm.prompt_builder import build_graph_prompt
from core.llm.validator import validate_answer

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Maximum context size in bytes to stay under Groq API limit.
MAX_CONTEXT_SIZE_BYTES = 10000


def _json_size(value: object) -> int:
    """Return serialized JSON size in bytes."""
    return len(json.dumps(value, default=str).encode("utf-8"))


def _trim_snapshot(snapshot: dict) -> bool:
    """Trim lowest-priority graph snapshot items first."""
    links = snapshot.get("links") or []
    nodes = snapshot.get("nodes") or []
    if links:
        snapshot["links"] = links[: max(len(links) // 2, 0)]
        return True
    if nodes:
        snapshot["nodes"] = nodes[: max(len(nodes) // 2, 0)]
        return True
    return False


def _truncate_context(context: dict, max_size: int = MAX_CONTEXT_SIZE_BYTES) -> dict:
    """Truncate all graph context fields until the total payload fits."""
    context = json.loads(json.dumps(context, default=str))
    while _json_size(context) > max_size:
        snapshot = context.get("snapshot")
        if isinstance(snapshot, dict) and _trim_snapshot(snapshot):
            continue
        remediations = context.get("remediations") or []
        if len(remediations) > 1:
            context["remediations"] = remediations[:-1]
            continue
        if len(remediations) == 1:
            context.pop("remediations", None)
            continue
        paths = context.get("attack_paths") or []
        if len(paths) > 1:
            context["attack_paths"] = paths[:-1]
            continue
        if len(paths) == 1 and _json_size(paths[0]) > max_size:
            context["attack_paths"] = []
            continue
        if snapshot:
            context.pop("snapshot", None)
            continue
        break
    return context


def _service_filter(question: str) -> str | None:
    """Return a known service name when the user scopes the question to it."""
    lowered = question.lower()
    try:
        rows = graph.execute("MATCH (s:Service) RETURN s.name AS name LIMIT 200")
    except Exception:
        return None
    service_names = sorted(
        (row.get("name") for row in rows if row.get("name")),
        key=len,
        reverse=True,
    )
    for service_name in service_names:
        if service_name.lower() in lowered:
            return service_name
    return None


def graph_context(question: str) -> dict:
    lowered = question.lower()
    service_name = _service_filter(question)
    raw_paths = graph.attack_paths(limit=10, service_name=service_name)
    context = {"attack_paths": raw_paths}
    if service_name:
        context["service_filter"] = service_name

    if "patch" in lowered or "fix" in lowered or "remediation" in lowered:
        context["remediations"] = ranked_remediations(limit=5)
    if "graph" in lowered or "show" in lowered:
        context["snapshot"] = graph.graph_snapshot()
    return _truncate_context(context)


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

    # Try Groq API with smart fallback on any error
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response = await client.post(GROQ_URL, headers=headers, json=payload)
            response.raise_for_status()
        answer = response.json()["choices"][0]["message"]["content"]
        validation = validate_answer(answer, context)
        if not validation["valid"]:
            answer = deterministic_answer(question, context)
            validation = validate_answer(answer, context)
        return {"answer": answer, "context": context, "validation": validation, "model": "llama-3.1-8b-instant"}
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        # Fallback to deterministic answer on API errors (413, timeout, etc.)
        answer = deterministic_answer(question, context)
        validation = validate_answer(answer, context)
        return {
            "answer": answer,
            "context": context,
            "validation": validation,
            "model": "deterministic-fallback",
            "error": f"LLM API error: {type(exc).__name__}"
        }
