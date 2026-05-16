from __future__ import annotations

from datetime import date, datetime


FEATURE_NAMES = [
    "cvss_score",
    "epss_score",
    "age_in_days",
    "has_public_exploit",
    "patch_available",
    "cvss_attack_vector_network",
    "cvss_complexity_low",
    "num_affected_packages",
    "threat_actor_count",
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
    return [
        float(cve.get("cvss_score", 0.0)),
        float(cve.get("epss_score", 0.0)),
        float(age),
        float(bool(cve.get("has_public_exploit") or cve.get("exploit_in_wild"))),
        float(bool(cve.get("patch_available"))),
        float(vector in ("network", "n")),
        float(complexity in ("low", "l")),
        float(cve.get("num_affected_packages", 1)),
        float(cve.get("threat_actor_count", 0)),
    ]
