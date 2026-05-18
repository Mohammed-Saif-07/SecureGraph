from __future__ import annotations

import re


def validate_answer(answer: str, context: dict) -> dict:
    """Validate that CVE claims in the LLM answer are grounded in the graph context.

    Returns a dict with:
      - ``valid``: True when the answer is well grounded enough to surface to the user.
        Accepted when there are no CVE claims, or when at least half of the cited
        CVEs are present in the context. This avoids discarding a useful, mostly
        grounded answer because the LLM mentioned one CVE from its training data
        that was trimmed out of the context. Callers can still inspect
        ``unsupported_claims`` to flag the answer in the UI.
      - ``unsupported_claims``: list of CVE IDs cited by the answer but missing
        from the context — surfaced for transparency even when ``valid`` is True.
    """
    context_text = str(context)
    claims = set(re.findall(r"CVE-\d{4}-\d+", answer))
    unsupported = [claim for claim in claims if claim not in context_text]
    if not claims:
        valid = True
    else:
        grounded = len(claims) - len(unsupported)
        valid = grounded * 2 >= len(claims)
    return {"valid": valid, "unsupported_claims": unsupported}
