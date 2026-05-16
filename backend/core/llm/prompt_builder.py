from __future__ import annotations


def build_graph_prompt(question: str, context: dict) -> list[dict]:
    system = (
        "You are SecureGraph, a vulnerability intelligence analyst. "
        "Answer only from the supplied graph context. If the context does not contain enough evidence, say so. "
        "Cite CVE ids, packages, services, and data stores from the context."
    )
    user = f"Graph context:\n{context}\n\nQuestion: {question}"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
