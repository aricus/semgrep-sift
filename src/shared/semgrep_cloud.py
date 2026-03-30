import datetime
from typing import Any, Optional

import httpx

SEMGREP_API_BASE = "https://semgrep.dev"


class SemgrepCloudClient:
    def __init__(self, token: str, base_url: str = SEMGREP_API_BASE) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "semgrep-sift/0.1.0",
        }

    def _get(self, client: httpx.Client, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        response = client.get(url, headers=self.headers, params=params or {}, timeout=60.0)
        response.raise_for_status()
        return response.json()

    def get_deployments(self, client: httpx.Client) -> list[dict]:
        data = self._get(client, "/api/v1/deployments")
        return data.get("deployments", [])

    def fetch_findings(
        self,
        client: httpx.Client,
        deployment_id: str,
        start_date: Optional[datetime.date] = None,
        end_date: Optional[datetime.date] = None,
        page_size: int = 100,
    ) -> list[dict]:
        findings: list[dict] = []
        page = 0

        while True:
            params: dict[str, Any] = {
                "deployment_id": deployment_id,
                "page": page,
                "size": page_size,
            }
            if start_date:
                params["start_date"] = start_date.isoformat()
            if end_date:
                params["end_date"] = end_date.isoformat()

            data = self._get(client, "/api/v1/findings", params=params)
            batch = data.get("findings", [])
            if not batch:
                break

            findings.extend(batch)
            if len(batch) < page_size:
                break
            page += 1

        return findings
