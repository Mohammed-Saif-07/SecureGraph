from __future__ import annotations


def score_path(path: dict) -> float:
    nodes = path.get("nodes", [])
    cve = next((n.get("properties", n) for n in nodes if "CVE" in n.get("labels", [])), {})
    data = next((n.get("properties", n) for n in nodes if "BusinessData" in n.get("labels", [])), {})
    exploitability = cve.get("real_risk_score") or cve.get("epss_score") or (cve.get("cvss_score", 0) / 10)
    impact = {"PCI-DSS": 1.0, "PHI": 0.95, "Confidential": 0.8}.get(data.get("classification"), 0.55)
    return round(exploitability * impact * 10, 2)


def blast_radius(paths: list[dict]) -> dict:
    services = {p.get("service_name") for p in paths if p.get("service_name")}
    data = {p.get("data_name") for p in paths if p.get("data_name")}
    return {"affected_services": len(services), "reachable_data_stores": len(data)}
