"""
SIH26159 SecureMailScope — Pydantic Data Models & Types
Conforms to docs/01-schema.md and docs/02-module-interfaces.md.
"""

from __future__ import annotations
from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field

class TLSDetails(BaseModel):
    observed_version: Optional[str] = None
    client_hello_max: Optional[str] = None
    cipher_suite_iana: Optional[str] = None
    cipher_suite_code: Optional[int] = None
    key_exchange: Optional[str] = None
    pfs: bool = False
    aead: bool = False
    client_random: Optional[str] = None
    server_random: Optional[str] = None
    ja3s: Optional[str] = None
    ja4s: Optional[str] = None
    session_resumption: bool = False

class X509Details(BaseModel):
    subject_cn: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    rsa_modulus_bits: Optional[int] = None
    sig_algo: Optional[str] = None
    chain_len: int = 0
    validated: bool = False
    validation_error: Optional[str] = None
    observable: bool = True

class FlowRecord(BaseModel):
    capture_session_id: str
    file: str
    flow_id: str
    server_ip: str
    server_port: int
    client_ip: str
    mx_domain: str
    service: str  # smtp | imap | pop3 | implicit-smtp | implicit-imap | implicit-pop3
    starttls_category: str  # advertised | advertised_unused | stripped | injected | implicit | none_clear
    tls: Optional[TLSDetails] = None
    x509: Optional[X509Details] = None
    features: List[float] = Field(default_factory=list)
    entropy: Dict[str, Any] = Field(default_factory=dict)
    raw_packets_count: int = 0
    first_byte_offset: Optional[str] = None
    sample_payload_hex: Optional[str] = None
    sample_payload_ascii: Optional[str] = None

class FindingProvenance(BaseModel):
    flow_id: str
    packet_no: int
    byte_offset: str
    tls_record_idx: int
    timestamp: str
    span_hash: str
    hex_snippet: str
    ascii_snippet: str

class Finding(BaseModel):
    id: Optional[int] = None
    session_id: str
    flow_id: str
    module: str
    rule_id: str
    title: str
    summary: str
    clause: str
    state: str  # SECURE | VULNERABLE | NOT-OBSERVABLE
    severity: str  # info | low | medium | high | critical
    cvss: float
    cwe: str
    confidence: float
    provenance: FindingProvenance

class SubScores(BaseModel):
    protocol: float
    cipher: float
    key: float
    x509: Union[float, str]  # can be float or "NOT-OBSERVABLE"
    dns: float
    enforce: float

class PostureScore(BaseModel):
    mx: str
    index: float
    ci_low: float
    ci_high: float
    grade: str
    confidence_label: str
    sub_scores: SubScores
    tri_state_summary: Dict[str, int]
    rubric: Dict[str, List[str]]

class HealthStatus(BaseModel):
    status: str = "ok"
    net: str = "offline"  # online | offline
    dns_ok: bool = False
    package_ver: str = "v1.4.0-sih"
    llm: str = "absent"  # ready | absent
    db_ok: bool = True

class SessionSummary(BaseModel):
    id: str
    source_file: str
    started_at: Optional[str] = None
    flow_count: int = 0
    package_ver: str
    report_hash: Optional[str] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    ci_range: Optional[List[float]] = None
    warnings: List[str] = Field(default_factory=list)
