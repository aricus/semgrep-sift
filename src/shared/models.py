from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, Field


class FindingsRequest(BaseModel):
    token: str = Field(..., min_length=1, description="Semgrep API token")
    start_date: Optional[date] = Field(None, description="Inclusive start date")
    end_date: Optional[date] = Field(None, description="Inclusive end date")


class Finding(BaseModel):
    id: str
    rule_name: str
    rule_message: str
    severity: str
    confidence: str
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    repository: str
    branch: str
    triage_state: Optional[str] = None
    state: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None
    url: Optional[str] = None

    class Config:
        extra = "allow"


class FindingsResponse(BaseModel):
    findings: list[Finding]
    count: int
    exported_at: datetime
