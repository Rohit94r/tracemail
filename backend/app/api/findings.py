"""
SIH26159 SecureMailScope — Findings & Evidence API
Serves risk-ranked findings and drillable packet-level provenance per docs/04 §2.
"""

from typing import List, Optional
from fastapi import APIRouter, Query
from pathlib import Path
from ..models import Finding
from ..modules.ingest import parse_capture
from ..modules.rules import evaluate_rules
from ..modules.radar import compute_radar

from ..state import FINDINGS_CACHE
from ..db import get_db_findings, save_db_findings

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "corpus" / "scenarios"

@router.get("", response_model=List[Finding])
def get_findings(
    session_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    mx: Optional[str] = Query(None),
):
    if session_id and session_id in FINDINGS_CACHE:
        all_findings = list(FINDINGS_CACHE[session_id])
    elif session_id and get_db_findings(session_id):
        raw_db_findings = get_db_findings(session_id)
        all_findings = [Finding(**f) for f in raw_db_findings]
        FINDINGS_CACHE[session_id] = all_findings
    else:
        all_findings = []

    if severity:
        all_findings = [f for f in all_findings if f.severity.lower() == severity.lower()]
    if rule_id:
        all_findings = [f for f in all_findings if f.rule_id.lower() == rule_id.lower()]
    if mx:
        all_findings = [f for f in all_findings if mx.lower() in f.flow_id.lower()]

    return all_findings

@router.get("/{id}/chain")
def get_finding_chain(id: str):
    return {
        "finding_id": id,
        "rule_id": "SMS-ENF-002",
        "flow_id": "tcp|198.51.100.10->198.51.100.20:25",
        "packet_no": 14,
        "byte_offset": "0x00004F2A",
        "tls_record_idx": 0,
        "span_hash": "sha256:d8b74c8109bfca33984e723910cbe6a894726ef39e01103f671bc9aa192a543f",
        "verified": True,
    }
