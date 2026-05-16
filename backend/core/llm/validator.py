from __future__ import annotations

import re


def validate_answer(answer: str, context: dict) -> dict:
    context_text = str(context)
    claims = set(re.findall(r"CVE-\d{4}-\d+", answer))
    unsupported = [claim for claim in claims if claim not in context_text]
    return {"valid": not unsupported, "unsupported_claims": unsupported}
