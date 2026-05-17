from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from subprocess import run
from urllib.parse import urlparse

from core.graph_engine import graph
from core.ingestion.osv_ingester import query_osv

logger = logging.getLogger(__name__)
NO_DEPENDENCY_MESSAGE = "No dependency files (requirements.txt, package.json) found in repository"
REPO_ACCESS_MESSAGE = "Repository not accessible. Check URL or provide GitHub token in .env"


class ScanError(Exception):
    """Raised when a repository cannot be scanned safely."""


def parse_requirements(text: str) -> list[dict]:
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.!-]+)?", line)
        if match:
            packages.append({"name": match.group(1).lower(), "version": match.group(2) or "unknown", "ecosystem": "PyPI"})
    return packages


def parse_package_json(text: str) -> list[dict]:
    payload = json.loads(text)
    deps = {}
    deps.update(payload.get("dependencies", {}))
    deps.update(payload.get("devDependencies", {}))
    return [
        {"name": name, "version": version.replace("^", "").replace("~", ""), "ecosystem": "npm"}
        for name, version in deps.items()
    ]


def _safe_repo_name(url: str) -> str:
    parsed = urlparse(url)
    bits = [bit for bit in parsed.path.split("/") if bit]
    return bits[-1].replace(".git", "") if bits else "ImportedService"


def _clone_url(repo_url: str) -> str:
    """Inject GitHub token into HTTPS clone URL when configured."""
    token = os.getenv("GITHUB_TOKEN", "")
    if not token or not repo_url.startswith("https://github.com/"):
        return repo_url
    return repo_url.replace("https://github.com/", f"https://x-access-token:{token}@github.com/", 1)


def extract_dependencies_from_repo(repo_url: str) -> tuple[str, list[dict]]:
    with tempfile.TemporaryDirectory() as tmp:
        result = run(["git", "clone", "--depth", "1", _clone_url(repo_url), tmp], capture_output=True, text=True, timeout=45)
        if result.returncode != 0:
            logger.warning("Repository clone failed for %s: %s", repo_url, result.stderr.strip())
            raise ScanError(REPO_ACCESS_MESSAGE)
        root = Path(tmp)
        packages: list[dict] = []
        req = root / "requirements.txt"
        pkg = root / "package.json"
        if req.exists():
            packages.extend(parse_requirements(req.read_text()))
        if pkg.exists():
            packages.extend(parse_package_json(pkg.read_text()))
        if not packages:
            logger.info("No dependency manifests found while scanning %s", repo_url)
        return _safe_repo_name(repo_url), packages


async def scan_packages(service_name: str, packages: list[dict]) -> dict:
    matched_packages = []
    results = []
    for package in packages:
        vulns = []
        try:
            vulns = await query_osv(package["name"], package["version"], package["ecosystem"])
        except Exception:
            vulns = []
        cve_ids = []
        for vuln in vulns[:8]:
            cve_id = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")), vuln.get("id"))
            if not cve_id:
                continue
            cve = {
                "id": cve_id,
                "description": vuln.get("summary", vuln.get("details", ""))[:2000],
                "cvss_score": 7.5,
                "epss_score": 0.35,
                "published_date": vuln.get("published", "")[:10],
                "severity": "high",
                "patch_available": bool(vuln.get("affected")),
                "exploit_in_wild": False,
            }
            graph.upsert_cve(cve)
            cve_ids.append(cve_id)
            results.append({"cve_id": cve_id, "package_name": package["name"], "risk_score": 7.5})
        demo_matches = graph.execute(
            """
            MATCH (c:CVE)-[:AFFECTS]->(p:Package {name: $name})
            RETURN c.id AS cve_id, coalesce(c.real_risk_score, c.epss_score, c.cvss_score / 10.0) AS risk
            """,
            name=package["name"],
        )
        cve_ids.extend([row["cve_id"] for row in demo_matches])
        results.extend({"cve_id": row["cve_id"], "package_name": package["name"], "risk_score": round(row["risk"] * 10, 2)} for row in demo_matches)
        if cve_ids:
            package_with_latest = {**package, "latest_version": "latest safe release"}
            graph.upsert_package(package_with_latest, sorted(set(cve_ids)))
            matched_packages.append(package_with_latest)
    if matched_packages:
        graph.create_service_context(service_name, matched_packages)
    paths = graph.attack_paths()
    return {"service": service_name, "packages": packages, "results": results, "attack_paths": paths}


async def scan_repo(repo_url: str) -> dict:
    service_name, packages = extract_dependencies_from_repo(repo_url)
    if not packages:
        return {"service": service_name, "packages": [], "results": [], "attack_paths": [], "message": NO_DEPENDENCY_MESSAGE}
    return await scan_packages(service_name, packages)
