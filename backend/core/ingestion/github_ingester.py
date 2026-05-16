from __future__ import annotations

import httpx

from core.config import settings

GRAPHQL_URL = "https://api.github.com/graphql"


async def fetch_github_advisories(ecosystem: str = "PIP", first: int = 20) -> list[dict]:
    if not settings.github_token:
        return []
    query = """
    query($ecosystem: SecurityAdvisoryEcosystem!, $first: Int!) {
      securityAdvisories(first: $first, ecosystem: $ecosystem, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
        nodes {
          ghsaId
          summary
          severity
          identifiers { type value }
          vulnerabilities(first: 10) {
            nodes { package { name ecosystem } vulnerableVersionRange firstPatchedVersion { identifier } }
          }
        }
      }
    }
    """
    headers = {"Authorization": f"Bearer {settings.github_token}"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(GRAPHQL_URL, json={"query": query, "variables": {"ecosystem": ecosystem, "first": first}}, headers=headers)
        response.raise_for_status()
        return response.json().get("data", {}).get("securityAdvisories", {}).get("nodes", [])
