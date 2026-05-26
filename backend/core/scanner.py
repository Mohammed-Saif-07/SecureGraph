from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import tomllib
from pathlib import Path
from subprocess import run
from urllib.parse import urlparse

from core.graph_engine import graph
from core.ingestion.osv_ingester import query_osv

logger = logging.getLogger(__name__)
NO_DEPENDENCY_MESSAGE = "No dependency files (requirements.txt, package.json, package-lock.json, pyproject.toml) found in repository"
REPO_ACCESS_MESSAGE = "Repository not accessible. Check URL or provide GitHub token in .env"
IGNORED_SCAN_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", ".next", "__pycache__"}
MANIFEST_NAMES = {"requirements.txt", "package.json", "package-lock.json", "pyproject.toml"}
MANIFEST_SCAN_LIMIT = int(os.getenv("MANIFEST_SCAN_LIMIT", "40"))
SCAN_PACKAGE_LIMIT = int(os.getenv("SCAN_PACKAGE_LIMIT", "120"))
OSV_VULN_LIMIT = int(os.getenv("OSV_VULN_LIMIT", "100"))


class ScanError(Exception):
    """Raised when a repository cannot be scanned safely."""


def _clean_version(version: object) -> str:
    value = str(version or "unknown").strip()
    value = re.sub(r"^[~^=<>\!\s]+", "", value)
    return value.split(" ", 1)[0] or "unknown"


def _dedupe_packages(packages: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for package in packages:
        name = str(package.get("name", "")).lower().strip()
        if not name:
            continue
        ecosystem = str(package.get("ecosystem", "unknown"))
        version = _clean_version(package.get("version"))
        key = (name, ecosystem, version)
        if key in seen:
            continue
        seen.add(key)
        deduped.append({**package, "name": name, "ecosystem": ecosystem, "version": version})
    return deduped


def parse_requirements(text: str) -> list[dict]:
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(("-r ", "--")):
            continue
        line = line.split("#", 1)[0].strip()
        line = re.sub(r";.*$", "", line)
        match = re.match(
            r"([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.!+*-]+)?",
            line,
        )
        if match:
            packages.append({"name": match.group(1).lower(), "version": _clean_version(match.group(2)), "ecosystem": "PyPI"})
    return packages


def parse_package_json(text: str) -> list[dict]:
    payload = json.loads(text)
    deps: dict[str, object] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps.update(payload.get(key, {}))
    return [{"name": name.lower(), "version": _clean_version(version), "ecosystem": "npm"} for name, version in deps.items()]


def parse_package_lock(text: str) -> list[dict]:
    payload = json.loads(text)
    packages = []
    for path, meta in payload.get("packages", {}).items():
        if not path.startswith("node_modules/"):
            continue
        name = path.replace("node_modules/", "", 1)
        if name and meta.get("version"):
            packages.append({"name": name.lower(), "version": _clean_version(meta["version"]), "ecosystem": "npm"})
    if packages:
        return packages
    for name, meta in payload.get("dependencies", {}).items():
        packages.append({"name": name.lower(), "version": _clean_version(meta.get("version")), "ecosystem": "npm"})
    return packages


def parse_pyproject(text: str) -> list[dict]:
    payload = tomllib.loads(text)
    dependencies: list[str] = []
    project = payload.get("project", {})
    dependencies.extend(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        dependencies.extend(group)
    poetry = payload.get("tool", {}).get("poetry", {})
    for name, value in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        version = value.get("version") if isinstance(value, dict) else value
        dependencies.append(f"{name}=={version}")
    return parse_requirements("\n".join(dependencies))


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


def _iter_manifest_files(root: Path) -> list[Path]:
    manifests = []
    for path in root.rglob("*"):
        if len(manifests) >= MANIFEST_SCAN_LIMIT:
            break
        if any(part in IGNORED_SCAN_DIRS for part in path.parts):
            continue
        if path.is_file() and path.name in MANIFEST_NAMES:
            manifests.append(path)
    return manifests


def _packages_from_manifest(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.name == "requirements.txt":
            return parse_requirements(text)
        if path.name == "package.json":
            return parse_package_json(text)
        if path.name == "package-lock.json":
            return parse_package_lock(text)
        if path.name == "pyproject.toml":
            return parse_pyproject(text)
    except Exception as exc:
        logger.warning("Could not parse dependency manifest %s: %s", path, exc)
    return []


def extract_dependencies_from_repo(repo_url: str) -> tuple[str, list[dict]]:
    with tempfile.TemporaryDirectory() as tmp:
        result = run(["git", "clone", "--depth", "1", _clone_url(repo_url), tmp], capture_output=True, text=True, timeout=45)
        if result.returncode != 0:
            logger.warning("Repository clone failed for %s: %s", repo_url, result.stderr.strip())
            raise ScanError(REPO_ACCESS_MESSAGE)
        root = Path(tmp)
        manifests = _iter_manifest_files(root)
        packages: list[dict] = []
        for manifest in manifests:
            packages.extend(_packages_from_manifest(manifest))
        packages = _dedupe_packages(packages)
        if not packages:
            logger.info("No dependency manifests found while scanning %s", repo_url)
        else:
            logger.info("Found %d dependencies in %d manifest(s) while scanning %s", len(packages), len(manifests), repo_url)
        return _safe_repo_name(repo_url), packages[:SCAN_PACKAGE_LIMIT]


async def scan_packages(service_name: str, packages: list[dict]) -> dict:
    packages = _dedupe_packages(packages)[:SCAN_PACKAGE_LIMIT]
    matched_packages = []
    results = []
    for package in packages:
        try:
            vulns = await query_osv(package["name"], package["version"], package["ecosystem"])
        except Exception as exc:
            logger.warning("OSV lookup failed for %s %s: %s", package["name"], package["version"], exc)
            vulns = []
        cve_ids = []
        for vuln in vulns[:OSV_VULN_LIMIT]:
            cve_id = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")), vuln.get("id"))
            if not cve_id:
                continue
            severity = "critical" if "critical" in (vuln.get("summary") or "").lower() else "high"
            risk = 9.0 if severity == "critical" else 7.5
            cve = {
                "id": cve_id,
                "description": vuln.get("summary", vuln.get("details", ""))[:2000],
                "cvss_score": risk,
                "epss_score": risk / 10,
                "published_date": vuln.get("published", "")[:10],
                "severity": severity,
                "patch_available": bool(vuln.get("affected")),
                "exploit_in_wild": risk >= 8,
                "real_risk_score": risk / 10,
            }
            graph.upsert_cve(cve)
            cve_ids.append(cve_id)
            results.append({"cve_id": cve_id, "package_name": package["name"], "risk_score": risk})

        graph_matches = graph.execute(
            """
            MATCH (c:CVE)-[:AFFECTS]->(p:Package {name: $name})
            RETURN c.id AS cve_id, coalesce(c.real_risk_score, c.epss_score, c.cvss_score / 10.0, 0.0) AS risk
            ORDER BY risk DESC
            LIMIT $limit
            """,
            name=package["name"],
            limit=OSV_VULN_LIMIT,
        )
        for row in graph_matches:
            cve_id = row.get("cve_id")
            if cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)
                results.append(
                    {"cve_id": cve_id, "package_name": package["name"], "risk_score": round(float(row.get("risk") or 0) * 10, 2)}
                )
        if cve_ids:
            package_with_latest = {**package, "latest_version": package.get("latest_version", "latest safe release")}
            graph.upsert_package(package_with_latest, sorted(set(cve_ids)))
            matched_packages.append(package_with_latest)

    unique_results = {}
    for result in results:
        key = (result["cve_id"], result["package_name"])
        if key not in unique_results or result["risk_score"] > unique_results[key]["risk_score"]:
            unique_results[key] = result
    results = sorted(unique_results.values(), key=lambda item: item.get("risk_score", 0), reverse=True)
    matched_packages = _dedupe_packages(matched_packages)
    if matched_packages:
        graph.create_service_context(service_name, matched_packages)
    paths = graph.attack_paths(service_name=service_name)
    return {"service": service_name, "packages": packages, "results": results, "attack_paths": paths}


async def scan_repo(repo_url: str) -> dict:
    service_name, packages = extract_dependencies_from_repo(repo_url)
    if not packages:
        return {"service": service_name, "packages": [], "results": [], "attack_paths": [], "message": NO_DEPENDENCY_MESSAGE}
    return await scan_packages(service_name, packages)
