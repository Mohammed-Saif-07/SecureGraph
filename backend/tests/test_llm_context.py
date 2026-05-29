from __future__ import annotations

from core.llm.graph_llm import deterministic_answer, graph_context


def test_cve_count_question_uses_summary_not_attack_path_limit(monkeypatch):
    class FakeGraph:
        def execute(self, query: str, **params):
            if "MATCH (s:Service)" in query:
                return []
            raise AssertionError("service lookup was the only expected raw query")

        def cve_summary(self, sample_limit: int = 10, service_name: str | None = None):
            return {
                "total": 52000,
                "sample_size": 2,
                "sample": [{"id": "CVE-2026-0002"}, {"id": "CVE-2026-0001"}],
            }

        def attack_paths(self, *args, **kwargs):
            raise AssertionError("count questions should not use attack path limits")

    monkeypatch.setattr("core.llm.graph_llm.graph", FakeGraph())

    context = graph_context("how many CVEs are in neo4j?")
    answer = deterministic_answer("how many CVEs are in neo4j?", context)

    assert context["cve_summary"]["total"] == 52000
    assert "52,000 CVE node" in answer
