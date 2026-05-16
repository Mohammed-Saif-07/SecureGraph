from __future__ import annotations

import httpx

OSV_URL = "https://api.osv.dev/v1/query"


async def query_osv(package_name: str, version: str, ecosystem: str) -> list[dict]:
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}, "version": version}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(OSV_URL, json=payload)
        response.raise_for_status()
        return response.json().get("vulns", [])
