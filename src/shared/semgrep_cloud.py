import datetime
import time
from typing import Any, Optional

import httpx

SEMGREP_API_BASE = "https://semgrep.dev"


def normalize_finding(raw: dict) -> dict:
    """Flatten a nested Semgrep SastFinding API response into a flat dict."""
    location = raw.get("location") or {}
    repository = raw.get("repository") or {}
    rule = raw.get("rule") or {}

    # Prefer nested rule.message/name if available, fall back to deprecated top-level fields
    rule_message = rule.get("message") if rule.get("message") else raw.get("rule_message")
    rule_name = rule.get("name") if rule.get("name") else raw.get("rule_name")

    return {
        "id": str(raw.get("id", "")),
        "rule_name": rule_name or "",
        "rule_message": rule_message or "",
        "severity": raw.get("severity", ""),
        "confidence": raw.get("confidence", ""),
        "path": location.get("file_path", ""),
        "line": location.get("line", 0) or 0,
        "column": location.get("column", 0) or 0,
        "end_line": location.get("end_line", 0) or 0,
        "end_column": location.get("end_column", 0) or 0,
        "repository": repository.get("name", ""),
        "branch": raw.get("ref", ""),
        "triage_state": raw.get("triage_state"),
        "state": raw.get("state"),
        "first_seen_at": None,
        "status": raw.get("status"),
        "created_at": raw.get("created_at"),
        "url": raw.get("line_of_code_url"),
    }


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

    def list_deployments(self, client: httpx.Client) -> list[dict]:
        """Fetch all deployments accessible with this token via the public v1 API."""
        data = self._get(client, "/api/v1/deployments")
        deployments = data.get("deployments", [])
        if not deployments:
            raise ValueError("No deployments found for this token")
        return deployments

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
            "issue_type": "sast",
            "page": page,
            "page_size": page_size,
            "dedup": "true",
        }
        if start_date:
            params["since"] = time.mktime(start_date.timetuple())

        while True:
            params["page"] = page
            data = self._get(client, f"/api/v1/deployments/{deployment_slug}/findings", params=params)

            # Correct response shape: {"sastFindings": {"findings": [...]}}
            sast_findings = data.get("sastFindings") or {}
            batch = sast_findings.get("findings", [])

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
