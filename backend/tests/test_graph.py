from __future__ import annotations

from core.attack_path.risk_scorer import blast_radius, score_path


def test_blast_radius_counts_unique_services_and_data():
    paths = [
        {"service_name": "PaymentService", "data_name": "PaymentDatabase"},
        {"service_name": "PaymentService", "data_name": "PaymentDatabase"},
        {"service_name": "AdminAPI", "data_name": "PaymentDatabase"},
    ]
    assert blast_radius(paths) == {"affected_services": 2, "reachable_data_stores": 1}


def test_score_path_uses_exploitability_and_business_impact():
    path = {
        "nodes": [
            {"labels": ["CVE"], "properties": {"real_risk_score": 0.9}},
            {"labels": ["BusinessData"], "properties": {"classification": "PCI-DSS"}},
        ]
    }
    assert score_path(path) == 9.0
