import csv
import io
import json
from datetime import datetime
from typing import Any

from src.shared.models import Finding


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "findings": [f.model_dump(mode="json") for f in findings],
            "count": len(findings),
            "exported_at": datetime.utcnow().isoformat() + "Z",
        },
        indent=2,
    )


def findings_to_csv(findings: list[Finding]) -> str:
    if not findings:
        return ""

    fieldnames = [
        "id",
        "rule_name",
        "rule_message",
        "severity",
        "confidence",
        "path",
        "line",
        "column",
        "end_line",
        "end_column",
        "repository",
        "branch",
        "triage_state",
        "state",
        "first_seen_at",
        "status",
        "created_at",
        "url",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        row: dict[str, Any] = {}
        for key in fieldnames:
            value = getattr(finding, key)
            row[key] = value if value is not None else ""
        writer.writerow(row)

    return output.getvalue()
