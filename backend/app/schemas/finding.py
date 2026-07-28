import uuid
from datetime import datetime

from pydantic import BaseModel


class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    module: str
    owasp_category: str
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: dict
    remediation: str
    created_at: datetime

    model_config = {"from_attributes": True}
