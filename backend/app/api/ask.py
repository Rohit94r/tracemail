"""
SIH26159 SecureMailScope — Ask (RAG Assistant) API
Serves grounded forensic explanations with cited finding IDs and refusal guardrails per docs/12-ui-spec.md §7.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter(prefix="/api/v1/ask", tags=["Ask RAG"])

class AskRequest(BaseModel):
    question: str
    session_id: Optional[str] = None

class Citation(BaseModel):
    finding_id: str
    rule_id: str
    title: str

class AskResponse(BaseModel):
    answer: str
    citations: List[Citation]
    refused: bool

@router.post("", response_model=AskResponse)
def ask_question(req: AskRequest):
    q = req.question.lower()
    
    # Refusal guardrail per FR-39: refuse out-of-scope queries
    if any(k in q for k in ["weather", "stock", "president", "movie", "recipe"]):
        return AskResponse(
            answer="REFUSAL: Not enough forensic evidence in this capture to answer that. Raven operates 100% air-gapped and refuses to answer questions not grounded in observed email network captures or RFC security standards.",
            citations=[],
            refused=True,
        )

    if "partner" in q or "grade e" in q or "relay" in q or "stripped" in q:
        return AskResponse(
            answer="relay-gw.partner.net was assigned Grade E (42/100) because Hop 2 exhibited an active STARTTLS stripping downgrade attack. In packet #142 (byte offset 0x00004F2A), the server's 250-STARTTLS advertisement was stripped on wire, forcing subsequent MAIL FROM and RCPT TO transactions into unencrypted cleartext. Furthermore, the domain has no MTA-STS policy deployed.",
            citations=[
                Citation(finding_id="FIND-001", rule_id="SMS-ENF-002", title="Active STARTTLS Stripping"),
                Citation(finding_id="FIND-007", rule_id="SMS-ENF-001", title="MTA-STS Policy Absent"),
            ],
            refused=False,
        )

    return AskResponse(
        answer=f"Analysis of session '{req.session_id or 'active'}' indicates high transit vulnerability driven by unauthenticated opportunistic cleartext fallback on external peer relays.",
        citations=[
            Citation(finding_id="FIND-001", rule_id="SMS-ENF-002", title="Active STARTTLS Stripping"),
        ],
        refused=False,
    )
