import datetime
import time
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

    def get_deployment(self, client: httpx.Client) -> dict:
        """Fetch current deployment using the agent endpoint (works with CLI tokens)."""
        data = self._get(client, "/api/agent/deployments/current")
        deployment = data.get("deployment")
        if not deployment:
            raise ValueError("No deployment found for this token")
        return deployment

    def fetch_findings(
        self,
        client: httpx.Client,
        deployment_slug: str,
        start_date: Optional[datetime.date] = None,
        end_date: Optional[datetime.date] = None,
        page_size: int = 100,
    ) -> list[dict]:
        findings: list[dict] = []
        page = 0

        params: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
            "dedup": "true",
        }
        if start_date:
            params["since"] = time.mktime(start_date.timetuple())

        while True:
            params["page"] = page
            data = self._get(client, f"/api/v1/deployments/{deployment_slug}/findings", params=params)

            # The API returns a list directly
            if not isinstance(data, list):
                batch = data.get("findings", [])
            else:
                batch = data

            if not batch:
                break

            findings.extend(batch)
            if len(batch) < page_size:
                break
            page += 1

        # Client-side end_date filtering if provided
        if end_date and findings:
            end_timestamp = time.mktime(end_date.timetuple())
            filtered = []
            for f in findings:
                relevant_since = f.get("relevant_since")
                if relevant_since is not None:
                    try:
                        if float(relevant_since) <= end_timestamp:
                            filtered.append(f)
                    except (ValueError, TypeError):
                        filtered.append(f)
                else:
                    filtered.append(f)
            findings = filtered

        return findings
