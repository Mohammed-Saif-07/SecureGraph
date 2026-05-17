from __future__ import annotations

from datetime import date, datetime


FEATURE_NAMES = [
    "cvss_score",
    "epss_score",
    "age_in_days",
    "cwe_numeric",
    "has_patch",
    "references_count",
]


def cve_to_features(cve: dict) -> list[float]:
    published = cve.get("published_date") or cve.get("published") or str(date.today())
    try:
        published_date = datetime.fromisoformat(published.replace("Z", "+00:00")).date()
    except ValueError:
        published_date = date.today()
    age = max((date.today() - published_date).days, 0)
    vector = (cve.get("cvss_attack_vector") or "").lower()
    complexity = (cve.get("cvss_complexity") or "").lower()
    cwe = str(cve.get("cwe_id") or "CWE-0")
    cwe_numeric = float(cwe.replace("CWE-", "").split("-")[0]) if cwe.replace("CWE-", "").split("-")[0].isdigit() else 0.0
    return [
        float(cve.get("cvss_score", 0.0)),
        float(cve.get("epss_score", 0.0)),
        float(age),
        cwe_numeric,
        float(bool(cve.get("has_patch") or cve.get("patch_available"))),
        float(cve.get("references_count", 0)),
    ]
