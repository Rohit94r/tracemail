"""
SIH26159 SecureMailScope — Ask (grounded RAG assistant, FR-39).

Three behaviours are guaranteed, in order of priority:

1. **Refusal outside scope.** Questions that are not about the capture or the
   analysis method are refused without calling the model.
2. **Refusal without evidence.** If retrieval finds nothing relevant, the
   request is refused rather than answered from general knowledge.
3. **Cite-or-refuse.** The model only ever sees retrieved spans, and every
   sentence it writes is verified against the span it cites. Unverifiable
   sentences are dropped; if none survive, the answer is a refusal.

Retrieval is local BM25 over RFC text, the scoring rubric, and the findings
computed for this capture. Generation is the single network call in the
product, and it receives only the question and the retrieved spans.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from ..modules.rag import answer as rag_answer, retrieve
from ..modules.rag.generator import _OUT_OF_SCOPE_KEYWORDS
from ..modules.report_builder import build_report

router = APIRouter(prefix="/api/v1/ask", tags=["Ask RAG"])


class AskRequest(BaseModel):
    question: str
    session_id: Optional[str] = None
    top_k: int = 6


class Citation(BaseModel):
    span_id: str
    source: str
    data_source: str
    rule_id: Optional[str] = None
    packet_no: Optional[int] = None


class AskResponse(BaseModel):
    answer: Optional[str]
    citations: List[Citation]
    rejected_sentences: List[Dict[str, Any]]
    refused: bool
    grounded: bool
    refusal_reason: Optional[str] = None
    model: Optional[str] = None
    retrieved_span_ids: List[str] = []


def _refusal(reason: str, model: Optional[str] = None, retrieved: Optional[List[dict]] = None) -> AskResponse:
    return AskResponse(
        answer=None,
        citations=[],
        rejected_sentences=[],
        refused=True,
        grounded=False,
        refusal_reason=reason,
        model=model,
        retrieved_span_ids=[s["span_id"] for s in (retrieved or [])],
    )


@router.post("", response_model=AskResponse)
def ask_question(req: AskRequest):
    q = (req.question or "").strip()
    if not q:
        return _refusal("empty question")

    # (1) Scope guardrail, before any model call.
    if any(k in q.lower() for k in _OUT_OF_SCOPE_KEYWORDS):
        return _refusal(
            "REFUSAL: outside the SecureMailScope evidence domain. The assistant "
            "answers only from the analysed capture, published RFC/NIST criteria "
            "and the scoring rubric, and has no other knowledge source."
        )

    # Resolve the session's findings so the retriever can ground on them.
    findings: List[dict] = []
    if req.session_id:
        try:
            findings = build_report(req.session_id).get("findings", [])
        except Exception:  # noqa: BLE001 - a bad session must not break the guardrail
            findings = []

    # (2) Evidence guardrail: no relevant span means no answer.
    pre = retrieve(q, findings, k=req.top_k)
    if not pre:
        return _refusal(
            "REFUSAL: no evidence in the capture, the RFC set or the scoring "
            "rubric addresses this question."
        )

    result = rag_answer(q, findings, k=req.top_k)

    if result["refused"]:
        return AskResponse(
            answer=None,
            citations=[],
            rejected_sentences=result.get("rejected", []),
            refused=True,
            grounded=False,
            refusal_reason=result.get("reason"),
            model=result.get("model"),
            retrieved_span_ids=[s["span_id"] for s in result.get("retrieved", [])],
        )

    return AskResponse(
        answer=result["answer"],
        citations=[Citation(**c) for c in result.get("citations", [])],
        rejected_sentences=result.get("rejected", []),
        refused=False,
        grounded=True,
        refusal_reason=None,
        model=result.get("model"),
        retrieved_span_ids=[s["span_id"] for s in result.get("retrieved", [])],
    )


@router.get("/retrieve")
def ask_retrieve_only(question: str, session_id: Optional[str] = None, top_k: int = 6):
    """
    Retrieval without generation.

    Exposed so an analyst can see exactly which spans the assistant is
    permitted to cite, and independently judge whether an answer could have
    been grounded. This endpoint makes no network call.
    """
    findings = build_report(session_id).get("findings", []) if session_id else []
    return {
        "question": question,
        "retrieved": retrieve(question, findings, k=top_k),
    }
