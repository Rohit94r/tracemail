"""
SIH26159 SecureMailScope — Delivery Graph API
Topology and weakest hop exposure model per docs/04 §2.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/api/v1/graph", tags=["Delivery Graph"])

class Node(BaseModel):
    id: str
    label: str
    type: str
    grade: str
    score: float

class Edge(BaseModel):
    source: str
    target: str
    volume: int
    percentage: float
    status: str
    is_weakest: bool = False

class GraphResponse(BaseModel):
    session_id: str
    nodes: List[Node]
    edges: List[Edge]
    weakest_hop: str
    exposure_summary: dict

@router.get("", response_model=GraphResponse)
@router.get("/{session_id}", response_model=GraphResponse)
def get_graph(session_id: str = ""):
    """
    Delivery topology derived from the analysed capture.

    Every node is an MX/relay that was actually observed in the session, and
    every edge is an observed hop between consecutive mail flows. Nothing is
    synthesised: an unanalysed session returns an empty, honest graph rather
    than a plausible-looking fabricated topology.
    """
    from ..state import FLOW_CACHE, MX_CACHE
    from ..db import get_db_sessions

    known = set(FLOW_CACHE) | {s.get("id") for s in get_db_sessions()}
    if not session_id or session_id not in known:
        return GraphResponse(
            session_id=session_id or "none",
            nodes=[],
            edges=[],
            weakest_hop="None",
            exposure_summary={},
        )

    flows = FLOW_CACHE.get(session_id) or []
    ordered = sorted(flows, key=lambda f: f.hop_index)

    # Grade/score come from the real posture computation for that MX, so the
    # graph never contradicts the posture screen.
    posture_by_mx = {}
    for entry in MX_CACHE.get(session_id) or []:
        posture_by_mx[entry.mx] = entry

    nodes: List[Node] = []
    seen: dict = {}
    for i, flow in enumerate(ordered):
        key = flow.mx_domain
        if key in seen:
            continue
        seen[key] = i
        posture = posture_by_mx.get(key)
        if posture is not None and posture.index is not None:
            grade, score = posture.grade or "N/A", posture.index
        elif flow.starttls_category in ("stripped", "none_clear"):
            grade, score = "Grade F", 0.0
        elif flow.tls is None:
            grade, score = "NOT-OBSERVABLE", 0.0
        else:
            grade, score = "NOT-OBSERVABLE", 0.0
        if flow.starttls_category in ("stripped", "none_clear"):
            ntype = "CLEARTEXT_MX"
        elif flow.tls and flow.tls.observed_version == "TLSv1.3":
            ntype = "TLS13_MX"
        elif flow.tls:
            ntype = "TLS_MX"
        else:
            ntype = "NO_TLS_OBSERVED"
        nodes.append(
            Node(
                id=f"hop{i}",
                label=key,
                type=ntype,
                grade=grade,
                score=score,
            )
        )

    total = len(ordered) or 1
    edges: List[Edge] = []

    # Exposure is measured per observed flow so a single-hop capture reports
    # 100% cleartext rather than 0% (there are no edges to count).
    cleartext = sum(
        1 for f in ordered
        if f.starttls_category in ("stripped", "none_clear")
    )
    tls13 = sum(
        1 for f in ordered
        if f.tls and f.tls.observed_version == "TLSv1.3"
    )
    weak = sum(
        1 for f in ordered
        if f.tls and (not f.tls.pfs or not f.tls.aead)
    )
    for a, b in zip(ordered, ordered[1:]):
        if a.mx_domain == b.mx_domain:
            continue
        cat = b.starttls_category
        if cat in ("stripped", "none_clear"):
            status = "STRIPPED_CLEARTEXT"
        elif b.tls and b.tls.observed_version == "TLSv1.3":
            status = "ENCRYPTED_TLS13"
        else:
            status = "ENCRYPTED_TLS"
        edges.append(
            Edge(
                source=f"hop{seen[a.mx_domain]}",
                target=f"hop{seen[b.mx_domain]}",
                volume=1,
                percentage=round(100.0 / total, 1),
                status=status,
                is_weakest=False,
            )
        )

    # The weakest hop is the one that actually leaked, if any leaked.
    weakest = "None"
    for edge in edges:
        if edge.status == "STRIPPED_CLEARTEXT":
            edge.is_weakest = True
            weakest = nodes[[n.id for n in nodes].index(edge.target)].label
            break

    return GraphResponse(
        session_id=session_id,
        nodes=nodes,
        edges=edges,
        weakest_hop=weakest,
        exposure_summary={
            "hops_observed": len(ordered),
            "cleartext_percentage": round(100.0 * cleartext / total, 1),
            "tls13_percentage": round(100.0 * tls13 / total, 1),
            "weak_ciphers_percentage": round(100.0 * weak / total, 1),
        },
    )
