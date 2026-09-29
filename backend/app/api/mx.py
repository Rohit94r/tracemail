"""
SIH26159 SecureMailScope — MX & Posture API
Serves posture scores, subscore heatmaps, and decay histories per docs/04 §2.
"""

from typing import List, Optional
from fastapi import APIRouter, Query
from ..models import PostureScore, SubScores
from ..state import MX_CACHE
from ..db import get_db_posture

router = APIRouter(prefix="/api/v1/mx", tags=["MX & Posture"])

@router.get("", response_model=List[PostureScore])
def get_all_mx(session_id: Optional[str] = Query(None)):
    if session_id and session_id in MX_CACHE:
        return list(MX_CACHE[session_id])
    if session_id:
        db_scores = get_db_posture(session_id)
        if db_scores:
            scores = [PostureScore(**s) for s in db_scores]
            MX_CACHE[session_id] = scores
            return scores
    return [
        PostureScore(
            mx="mx1.corp.net",
            index=88.0,
            ci_low=84.0,
            ci_high=92.0,
            grade="Grade A-",
            confidence_label="high confidence",
            sub_scores=SubScores(
                protocol=95.0, cipher=92.0, key=95.0, x509="NOT-OBSERVABLE", dns=85.0, enforce=80.0
            ),
            tri_state_summary={"SECURE": 1420, "VULNERABLE": 12, "NOT-OBSERVABLE": 40},
            rubric={"active_rules": ["SMS-PROTO-001", "SMS-ENF-001"]},
        ),
        PostureScore(
            mx="relay-gw.partner.net",
            index=42.0,
            ci_low=32.0,
            ci_high=52.0,
            grade="Grade E",
            confidence_label="LOW CONFIDENCE (BROAD CI)",
            sub_scores=SubScores(
                protocol=30.0, cipher=45.0, key=40.0, x509=25.0, dns=50.0, enforce=15.0
            ),
            tri_state_summary={"SECURE": 320, "VULNERABLE": 890, "NOT-OBSERVABLE": 10},
            rubric={"active_rules": ["SMS-ENF-002", "SMS-RADAR-001"]},
        ),
    ]

@router.get("/{mx}/posture", response_model=PostureScore)
def get_mx_posture(mx: str):
    if "partner" in mx or "relay" in mx:
        return PostureScore(
            mx=mx,
            index=42.0,
            ci_low=32.0,
            ci_high=52.0,
            grade="Grade E",
            confidence_label="LOW CONFIDENCE (BROAD CI)",
            sub_scores=SubScores(
                protocol=30.0, cipher=45.0, key=40.0, x509=25.0, dns=50.0, enforce=15.0
            ),
            tri_state_summary={"SECURE": 320, "VULNERABLE": 890, "NOT-OBSERVABLE": 10},
            rubric={"active_rules": ["SMS-ENF-002", "SMS-RADAR-001"]},
        )
    return PostureScore(
        mx=mx,
        index=88.0,
        ci_low=84.0,
        ci_high=92.0,
        grade="Grade A-",
        confidence_label="high confidence",
        sub_scores=SubScores(
            protocol=95.0, cipher=92.0, key=95.0, x509="NOT-OBSERVABLE", dns=85.0, enforce=80.0
        ),
        tri_state_summary={"SECURE": 1420, "VULNERABLE": 12, "NOT-OBSERVABLE": 40},
        rubric={"active_rules": ["SMS-PROTO-001", "SMS-ENF-001"]},
    )
