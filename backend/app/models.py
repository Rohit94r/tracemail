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
    key_exchange_source: str = "inferred-from-cipher-suite"
    pfs: bool = False
    pfs_source: str = "inferred-from-cipher-suite"
    aead: bool = False
    client_random: Optional[str] = None
    server_random: Optional[str] = None
    ja3s: Optional[str] = None
    ja4s: Optional[str] = None
    session_resumption: bool = False
    version_source: str = "wire"               # wire | unknown
    extensions: List[int] = Field(default_factory=list)

class CertSummary(BaseModel):
    """One certificate as it actually appeared on the wire."""
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    serial_hex: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    public_key_alg: Optional[str] = None
    public_key_bits: Optional[int] = None
    signature_alg: Optional[str] = None
    is_ca: bool = False
    self_signed: bool = False


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

    # --- Real analysis (added: previously these were derived, not observed) ---
    public_key_alg: Optional[str] = None       # RSA | EC | DSA | Ed25519 | unknown
    public_key_bits: Optional[int] = None       # modulus bits (RSA/DSA) or curve bits (EC)
    expired: Optional[bool] = None              # not_after < capture time
    days_until_expiry: Optional[int] = None
    certs: List[CertSummary] = Field(default_factory=list)  # full observed chain
    chain_complete: Optional[bool] = None       # leaf+intermediates actually seen
    chain_linkage_ok: Optional[bool] = None     # each issuer == next subject
    chain_root_included: Optional[bool] = None
    trust_anchor_present: bool = False          # only true if a real trust store matched
    trust_check_method: str = "not-performed"   # not-performed | offline-trust-store

class FlowRecord(BaseModel):
    capture_session_id: str
    file: str
    flow_id: str
    server_ip: str
    server_port: int
    client_ip: str
    mx_domain: str
    mx_domain_source: str = "ip-derived"  # cert-san | cert-cn | ip-derived
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

    # --- Real provenance: every finding points at a verified location ---
    first_packet_no: int = 0
    first_packet_timestamp: Optional[str] = None
    last_packet_no: int = 0
    byte_offset_exact: bool = False   # False => offset unavailable, never fabricated
    tls_record_packets: Dict[str, int] = Field(default_factory=dict)
    starttls_packets: Dict[str, int] = Field(default_factory=dict)
    packet_offsets: Dict[str, int] = Field(default_factory=dict)
    packet_timestamps: Dict[str, str] = Field(default_factory=dict)  # role -> packet_no
    hop_index: Optional[int] = None  # position in the delivery chain (D2)
    capture_time: Optional[str] = None
    capture_sha256: Optional[str] = None

class FindingProvenance(BaseModel):
    flow_id: str
    packet_no: int
    byte_offset: str
    tls_record_idx: int
    timestamp: str
    span_hash: str
    hex_snippet: str
    ascii_snippet: str
    byte_offset_exact: bool = True
    hop_index: Optional[int] = None

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
    capture_sha256: Optional[str] = None
    finding_count: int = 0
    created_epoch: Optional[float] = None


# --------------------------------------------------------------------------
# DNS policy (the one permitted network operation, per the product contract)
# --------------------------------------------------------------------------

class DNSPolicy(BaseModel):
    """Observed or fixture-sourced mail security policy for one domain."""
    domain: str
    source: str = "unavailable"      # live-dns | offline-fixture | unavailable
    dane_tlsa_present: Optional[bool] = None
    dane_usable: Optional[bool] = None       # usable_0 | usable_1
    mta_sts_present: Optional[bool] = None
    mta_sts_mode: Optional[str] = None       # enforce | testing | none
    mta_sts_max_age: Optional[int] = None
    spf_present: Optional[bool] = None
    dkim_present: Optional[bool] = None
    dmarc_present: Optional[bool] = None
    dmarc_policy: Optional[str] = None       # none | quarantine | reject
    error: Optional[str] = None


class EnforcementResult(BaseModel):
    """D3: does observed TLS match what policy demands?"""
    domain: str
    state: str                        # CONSISTENT | INCONSISTENT | NOT-OBSERVABLE
    observed_cipher: Optional[str] = None
    observed_tls_version: Optional[str] = None
    demanded_by: List[str] = Field(default_factory=list)
    detail: str = ""
    severity: str = "info"


# --------------------------------------------------------------------------
# Anomaly detection (deterministic + statistical; no trained model)
# --------------------------------------------------------------------------

class AnomalySignal(BaseModel):
    feature: str
    value: float
    expected_range: str
    z_score: float
    direction: str            # high | low
    method: str               # iqr | zscore | threshold
    explanation: str


class AnomalyReport(BaseModel):
    scope: str
    baseline_flows: int
    anomalous_flows: int
    signals: List[AnomalySignal] = Field(default_factory=list)
    flagged_flow_ids: List[str] = Field(default_factory=list)
    method_note: str = (
        "Deterministic statistics over observed features (IQR fences and z-score). "
        "No trained model and no randomness; identical input always yields identical output."
    )
