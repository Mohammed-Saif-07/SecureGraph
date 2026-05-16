from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from neo4j import GraphDatabase

from core.config import settings


@dataclass
class GraphNode:
    id: str
    label: str
    properties: dict[str, Any]


class GraphEngine:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    def close(self) -> None:
        self.driver.close()

    def execute(self, query: str, **params: Any) -> list[dict[str, Any]]:
        with self.driver.session() as session:
            result = session.run(query, **params)
            return [record.data() for record in result]

    def setup_schema(self) -> None:
        constraints = [
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT package_key IF NOT EXISTS FOR (p:Package) REQUIRE (p.name, p.ecosystem, p.version) IS UNIQUE",
            "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
            "CREATE CONSTRAINT server_host IF NOT EXISTS FOR (s:Server) REQUIRE s.hostname IS UNIQUE",
            "CREATE CONSTRAINT data_name IF NOT EXISTS FOR (d:BusinessData) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.name IS UNIQUE",
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:AttackTechnique) REQUIRE t.mitre_id IS UNIQUE",
        ]
        for constraint in constraints:
            self.execute(constraint)

    def upsert_cve(self, cve: dict[str, Any]) -> None:
        self.execute(
            """
            MERGE (c:CVE {id: $id})
            SET c += $props
            """,
            id=cve["id"],
            props=cve,
        )

    def upsert_package(self, package: dict[str, Any], cve_ids: list[str]) -> None:
        self.execute(
            """
            MERGE (p:Package {name: $name, ecosystem: $ecosystem, version: $version})
            SET p.latest_version = $latest_version
            WITH p
            UNWIND $cve_ids AS cve_id
            MATCH (c:CVE {id: cve_id})
            MERGE (c)-[:AFFECTS]->(p)
            """,
            **package,
            cve_ids=cve_ids,
        )

    def create_service_context(self, service_name: str, packages: list[dict[str, Any]]) -> None:
        self.execute(
            """
            MERGE (svc:Service {name: $service_name})
            SET svc.type = coalesce(svc.type, "application"),
                svc.criticality = coalesce(svc.criticality, "high"),
                svc.owner_team = coalesce(svc.owner_team, "platform")
            MERGE (srv:Server {hostname: $host})
            SET srv.ip = "10.0.8.15", srv.environment = "production", srv.cloud_provider = "local"
            MERGE (data:BusinessData {name: "PaymentDatabase"})
            SET data.classification = "PCI-DSS", data.regulatory_requirement = "PCI-DSS"
            MERGE (svc)-[:RUNS_ON]->(srv)
            MERGE (srv)-[:STORES]->(data)
            WITH svc
            UNWIND $packages AS pkg
            MATCH (p:Package {name: pkg.name, ecosystem: pkg.ecosystem, version: pkg.version})
            MERGE (p)-[:USED_BY]->(svc)
            """,
            service_name=service_name,
            host=f"{service_name.lower()}.prod.local",
            packages=packages,
        )

    def attack_paths(self, limit: int = 25) -> list[dict[str, Any]]:
        return self.execute(
            """
            MATCH path = (cve:CVE)-[:AFFECTS]->(pkg:Package)-[:USED_BY]->(svc:Service)
                         -[:RUNS_ON]->(srv:Server)-[:STORES]->(data:BusinessData)
            WITH path, cve, pkg, svc, data,
                 coalesce(cve.real_risk_score, cve.epss_score, cve.cvss_score / 10.0, 0.0) AS exploitability,
                 CASE coalesce(data.classification, "")
                   WHEN "PCI-DSS" THEN 1.0
                   WHEN "PHI" THEN 0.95
                   WHEN "Confidential" THEN 0.8
                   ELSE 0.55
                 END AS impact
            RETURN [node IN nodes(path) | {
                     id: coalesce(node.id, node.name, node.hostname, node.mitre_id),
                     labels: labels(node),
                     properties: properties(node)
                   }] AS nodes,
                   [rel IN relationships(path) | type(rel)] AS relationships,
                   length(path) AS hops,
                   round(10 * exploitability * impact, 2) AS risk_score,
                   cve.id AS cve_id,
                   pkg.name AS package_name,
                   svc.name AS service_name,
                   data.name AS data_name
            ORDER BY risk_score DESC, hops ASC
            LIMIT $limit
            """,
            limit=limit,
        )

    def graph_snapshot(self) -> dict[str, Any]:
        rows = self.execute(
            """
            MATCH (n)
            OPTIONAL MATCH (n)-[r]->(m)
            RETURN collect(DISTINCT {
              id: elementId(n),
              label: head(labels(n)),
              name: coalesce(n.id, n.name, n.hostname, n.mitre_id),
              severity: n.severity,
              risk: coalesce(n.real_risk_score, n.epss_score, n.cvss_score / 10.0)
            }) AS nodes,
            collect(DISTINCT {
              source: elementId(n),
              target: elementId(m),
              type: type(r)
            }) AS links
            """
        )
        snapshot = rows[0] if rows else {"nodes": [], "links": []}
        snapshot["links"] = [link for link in snapshot["links"] if link.get("target")]
        return snapshot

    def top_remediations(self, limit: int = 3) -> list[dict[str, Any]]:
        return self.execute(
            """
            MATCH (cve:CVE)-[:AFFECTS]->(pkg:Package)-[:USED_BY]->(svc:Service)
            WITH pkg, collect(DISTINCT cve.id) AS cves, collect(DISTINCT svc.name) AS services,
                 sum(coalesce(cve.real_risk_score, cve.epss_score, cve.cvss_score / 10.0, 0.0)) AS risk
            RETURN pkg.name AS package_name,
                   pkg.ecosystem AS ecosystem,
                   pkg.version AS current_version,
                   coalesce(pkg.latest_version, "latest safe release") AS fixed_version,
                   cves,
                   services,
                   round(risk * size(services), 2) AS risk_reduction
            ORDER BY risk_reduction DESC
            LIMIT $limit
            """,
            limit=limit,
        )

    def seed_demo_graph(self) -> None:
        existing = self.execute("MATCH (c:CVE) RETURN count(c) AS count")[0]["count"]
        if existing:
            return
        demo_cves = [
            {
                "id": "CVE-2023-32681",
                "description": "Requests proxy credential exposure scenario used as a demo high-risk chain.",
                "cvss_score": 9.1,
                "epss_score": 0.94,
                "published_date": "2023-05-26",
                "severity": "critical",
                "patch_available": True,
                "exploit_in_wild": True,
                "real_risk_score": 0.92,
            },
            {
                "id": "CVE-2023-44487",
                "description": "HTTP/2 rapid reset denial of service exposure.",
                "cvss_score": 7.5,
                "epss_score": 0.82,
                "published_date": "2023-10-10",
                "severity": "high",
                "patch_available": True,
                "exploit_in_wild": True,
                "real_risk_score": 0.88,
            },
            {
                "id": "CVE-2024-1234",
                "description": "Authentication bypass demo CVE for admin API exposure.",
                "cvss_score": 8.8,
                "epss_score": 0.67,
                "published_date": "2024-02-11",
                "severity": "high",
                "patch_available": True,
                "exploit_in_wild": False,
                "real_risk_score": 0.81,
            },
        ]
        for cve in demo_cves:
            self.upsert_cve(cve)
        packages = [
            {"name": "requests", "ecosystem": "PyPI", "version": "2.28.0", "latest_version": "2.31.0"},
            {"name": "aiohttp", "ecosystem": "PyPI", "version": "3.8.1", "latest_version": "3.9.0"},
            {"name": "pyjwt", "ecosystem": "PyPI", "version": "2.6.0", "latest_version": "2.8.0"},
        ]
        for package, cves in zip(packages, [["CVE-2023-32681"], ["CVE-2023-44487"], ["CVE-2024-1234"]]):
            self.upsert_package(package, cves)
        self.create_service_context("PaymentService", packages[:2])
        self.create_service_context("AdminAPI", packages[2:])
        self.execute(
            """
            MERGE (actor:ThreatActor {name: "APT28"})
            SET actor.origin = "Russia", actor.sophistication = "high", actor.motivation = "espionage"
            MERGE (tech:AttackTechnique {mitre_id: "T1110"})
            SET tech.name = "Credential Stuffing", tech.tactic = "Credential Access",
                tech.description = "Attempts to use credentials from password reuse."
            WITH actor, tech
            MATCH (c:CVE {id: "CVE-2023-32681"})
            MERGE (actor)-[:USES]->(tech)
            MERGE (tech)-[:EXPLOITS]->(c)
            """
        )


graph = GraphEngine()
