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
def get_graph(session_id: str = "active-session"):
    nodes = [
        Node(id="corp-mx1", label="mx1.corp.net", type="INTERNAL_MX", grade="A-", score=88.0),
        Node(id="peer-google", label="aspmx.l.google.com", type="PEER_MX", grade="A+", score=98.0),
        Node(id="peer-msft", label="mail.protection.outlook.com", type="PEER_MX", grade="A", score=92.0),
        Node(id="peer-weak-relay", label="relay-gw.partner.net", type="RELAY", grade="E", score=42.0),
    ]

    edges = [
        Edge(source="corp-mx1", target="peer-google", volume=2450, percentage=48.0, status="ENCRYPTED_TLS13", is_weakest=False),
        Edge(source="corp-mx1", target="peer-msft", volume=1220, percentage=24.0, status="ENCRYPTED_TLS13", is_weakest=False),
        Edge(source="corp-mx1", target="peer-weak-relay", volume=890, percentage=17.4, status="STRIPPED_CLEARTEXT", is_weakest=True),
    ]

    return GraphResponse(
        session_id=session_id,
        nodes=nodes,
        edges=edges,
        weakest_hop="relay-gw.partner.net",
        exposure_summary={
            "cleartext_percentage": 17.4,
            "tls13_percentage": 72.0,
            "weak_ciphers_percentage": 3.5,
        },
    )
