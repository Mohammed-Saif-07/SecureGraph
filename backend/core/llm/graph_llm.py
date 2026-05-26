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


def _service_filter(question: str, hint: str | None = None) -> str | None:
    """Return a known service name when the question (or caller hint) scopes to it.

    Priority order (explicit caller intent wins):
      1. ``hint`` — if the frontend told us which scan the user is viewing,
         that scope wins. This prevents demo-baseline services (PaymentService,
         PaymentDatabase) from leaking into answers when the user is actually
         asking about a freshly scanned repo.
      2. Question text — only used as a fallback when no hint is supplied,
         e.g. when the user navigates to Query without ever opening a scan.
    """
    try:
        rows = graph.execute("MATCH (s:Service) RETURN s.name AS name LIMIT 200")
    except Exception:
        return None
    service_names = sorted(
        (row.get("name") for row in rows if row.get("name")),
        key=len,
        reverse=True,
    )
    # 1. Honour the explicit hint first.
    if hint:
        hint_lower = hint.lower()
        for service_name in service_names:
            sn_lower = service_name.lower()
            if sn_lower == hint_lower or sn_lower in hint_lower or hint_lower in sn_lower:
                return service_name
    # 2. Fallback to question-text matching only when no hint resolved.
    lowered = question.lower()
    for service_name in service_names:
        if service_name.lower() in lowered:
            return service_name
    return None


def graph_context(question: str, service_hint: str | None = None) -> dict:
    lowered = question.lower()
    service_name = _service_filter(question, hint=service_hint)
    # When the query is scoped to a single service the candidate path set is
    # already narrow, so we pull a wider slice (50) to ensure every vulnerable
    # package attached to that service reaches the LLM. The unscoped/org-wide
    # case keeps the original tighter limit so we don't blow the prompt budget.
    path_limit = 50 if service_name else 10
    raw_paths = graph.attack_paths(limit=path_limit, service_name=service_name)
    context = {"attack_paths": raw_paths}
    if service_name:
        context["service_filter"] = service_name

    if "patch" in lowered or "fix" in lowered or "remediation" in lowered:
        # Scope remediations to the same service when the query is service-scoped
        # so the deterministic fallback doesn't recommend patches that belong to
        # a completely different repo than the one the user is asking about.
        context["remediations"] = ranked_remediations(limit=5, service_name=service_name)
    if "graph" in lowered or "show" in lowered:
        context["snapshot"] = graph.graph_snapshot()
    return _truncate_context(context)


def deterministic_answer(
    question: str,
    context: dict,
    unsupported_claims: list[str] | None = None,
) -> str:
    """Return a deterministic, graph-grounded answer.

    ``unsupported_claims`` is supplied by ``answer_question`` when the
    validator rejected the LLM's output because it referenced CVEs that aren't
    in the graph. Surfacing those rejected IDs back to the user makes the
    fallback honest about *why* it kicked in — otherwise users asking a trap
    question ("does CVE-2099-77777 exist?") see a generic path list instead
    of an explicit denial.
    """
    service_filter = context.get("service_filter")
    remediations = context.get("remediations") or ranked_remediations(
        limit=3, service_name=service_filter
    )
    if "patch" in question.lower() or "fix" in question.lower():
        if not remediations:
            return "The graph does not contain enough vulnerable package evidence to recommend patches yet."
        scope_phrase = f" in {service_filter}" if service_filter else ""
        lines = [f"Based on the graph, patch these packages first{scope_phrase}:"]
        for idx, item in enumerate(remediations[:3], start=1):
            lines.append(
                f"{idx}. Update {item['package_name']} from {item['current_version']} to {item['fixed_version']} "
                f"to reduce risk across {len(item['services'])} service(s): {', '.join(item['services'])}."
            )
        return "\n".join(lines)
    paths = context.get("attack_paths", [])
    if not paths and not unsupported_claims:
        return "The graph does not contain attack paths to business data yet."
    # When the LLM either wasn't called or produced an ungrounded answer, we
    # surface the strongest evidence the graph actually contains so the user
    # still gets something useful — not just the single highest-risk path.
    scope_phrase = f" for {service_filter}" if service_filter else ""
    lines: list[str] = []
    if unsupported_claims:
        claim_list = ", ".join(sorted(set(unsupported_claims)))
        if paths:
            lines.append(
                f"I couldn't find {claim_list} in the graph context, so I can't confirm it exists or affects this service. "
                f"Here are the strongest attack paths I do have evidence for{scope_phrase}:"
            )
        else:
            return (
                f"I couldn't find {claim_list} in the graph context, so I can't confirm it exists or affects this service. "
                f"The graph also doesn't yet contain attack paths{scope_phrase} to compare against."
            )
    else:
        lines.append(
            f"Here are the strongest attack paths grounded in the graph{scope_phrase}:"
        )
    for idx, path in enumerate(paths[:3], start=1):
        lines.append(
            f"{idx}. {path['cve_id']} affects {path['package_name']}, used by "
            f"{path['service_name']} ({path['hops']} hops to {path['data_name']}). "
            f"Risk score: {path['risk_score']}/10."
        )
    return "\n".join(lines)


async def answer_question(question: str, service_hint: str | None = None) -> dict:
    context = graph_context(question, service_hint=service_hint)
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
            # Pass the rejected CVE IDs into the fallback so the deterministic
            # answer can explicitly tell the user "I couldn't find X" rather
            # than silently swapping their question for a generic path list.
            answer = deterministic_answer(
                question, context, unsupported_claims=validation["unsupported_claims"]
            )
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
