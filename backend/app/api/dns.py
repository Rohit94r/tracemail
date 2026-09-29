"""
SIH26159 SecureMailScope — DNS Policy & Anomaly API.

DNS policy reads are the only permitted network operation in the product.
Anomaly scores are deterministic threshold statistics, never a trained model.
"""

from fastapi import APIRouter, Query
from typing import List, Optional

from ..models import AnomalyReport, DNSPolicy, EnforcementResult
from ..modules.anomaly import detect_anomalies
from ..modules.dns_policy import enforcement, lookup_policy, policy_findings
from ..state import FLOW_CACHE

router = APIRouter(prefix="/api/v1", tags=["DNS & Anomaly"])


@router.get("/dns/policy", response_model=DNSPolicy)
def get_dns_policy(mx: str = Query(...), live: bool = Query(True)):
    """MTA-STS / DANE / SPF / DKIM / DMARC posture for one mail host."""
    return lookup_policy(mx, live=live)


@router.get("/dns/findings")
def get_dns_findings(mx: str = Query(...), live: bool = Query(True)):
    """SMS-DNS-* findings derived from the resolved policy."""
    """SMS-DNS-* findings derived from the resolved policy."""
    return {
        "mx": mx,
        "findings": policy_findings(mx, live=live),
    }


@router.get("/anomaly/{session_id}", response_model=AnomalyReport)
def get_anomaly(session_id: str):
    """
    Deterministic anomaly report for an analysed session.

    Returns an empty, zero-score report for an unknown session rather than a
    plausible-looking placeholder.
    """
    return detect_anomalies(FLOW_CACHE.get(session_id) or [], session_id)


@router.get("/enforcement", response_model=EnforcementResult)
def get_enforcement(
    domain: str = Query(...),
    observed_cipher: Optional[str] = Query(None),
    live: bool = Query(True),
):
    """D3: does observed TLS satisfy what published policy demands?"""
    return enforcement(domain, observed_cipher, live=live)


@router.get("/anomalies")
def get_anomalies(session_id: Optional[str] = Query(None)):
    """Batch form; an absent session_id returns an empty list, not a guess."""
    if not session_id:
        return {"session_id": None, "anomalies": []}
    return {
        "session_id": session_id,
        "anomalies": [detect_anomalies(FLOW_CACHE.get(session_id) or [], session_id)],
    }
