"""
SIH26159 SecureMailScope — Health API
Backs the offline air-gap badge and package ver chip per docs/12-ui-spec.md §0.
"""

from fastapi import APIRouter
from ..models import HealthStatus
from ..config import PACKAGE_VER
from ..db import ping_db

router = APIRouter(prefix="/api/v1", tags=["Health"])

@router.get("/health", response_model=HealthStatus)
def get_health():
    db_ok = ping_db()

    return HealthStatus(
        status="ok",
        net="online" if db_ok else "offline",
        dns_ok=False,
        package_ver=PACKAGE_VER,
        llm="absent",
        db_ok=db_ok,
    )
