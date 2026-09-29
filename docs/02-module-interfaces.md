# SIH26159 SecureMailScope — 02. Module Interfaces

Design-only. These are the contracts each module module must satisfy. Signatures are the intended API — parameter names/return shapes are fixed pre-code.

---

## Module 1 — Ingest/Parse

**Inputs:** capture file(s) (pcap/pcapng), an optional `tspark`/`zeek_ssl_log` companion.
**Outputs:** `list[FlowRecord]` (schema doc §1) + session metadata.

```python
@dataclass
class ParseOptions:
    use_zeek: bool = False            # zeek ssl.log/x509.log enrichment path (optional)
    resolve_peers: bool = True        # map server_ip -> mx_domain via captured/static peers

def parse_capture(path: Path, opts: ParseOptions) -> ParseResult: ...
@dataclass
class ParseResult:
    session_id: str
    flows: list[FlowRecord]
    warning: list[str]                # e.g. "tspark missing, used scapy", "pcap truncated"
```

Implementation path (in order): tshark via `pyshark` → fallback `scapy`; STARTTLS state machine per service grammar; X.509 decoded via `cryptography`.

## Module 2 — Feature Layer

**Inputs:** `list[FlowRecord]`.
**Outputs:** features written into each record (25-vector, Appendix A order), plus entropy stats.

```python
def build_features(flows: list[FlowRecord]) -> list[FlowRecord]: ...
```

Attaches `ja3s`, `ja4s`, computed cipher-family/FS enum, `client_random` histogram entropy + repeat-bucket, cert attribute enums.

## Module 3 — Rule Engine

**Inputs:** flow + features.
**Outputs:** `[Finding]` each with `rule_id → RFC/NIST clause → state → severity → cvss → cwe` PLUS per-serviceMX sub-score contributions.

```python
def evaluate_rules(flows: list[FlowRecord]) -> RuleResults: ...
@dataclass
class RuleResults:
    findings: list[Finding]
    sub_scores: dict[tuple[str, str], SubScores]   # (mx,service) -> 6 sub-scores
```

Ground-truth sources: RFC 9325, NIST SP 800-52r2, RFC 5280 §6, RFC 6698/7672/8461/8460. Exact rule catalog in `docs/03-scoring-rubric.md`.

## Module 4 — Posture Scoring (confidence-bounded)

```python
def compute_posture(sub_scores: ... ,
                    evidence_observability: EvidenceObservability) -> PostureScore:
@dataclass
class PostureScore:
    index: float                      # 0..100
    ci_low: float; ci_high: float     # confidence interval
    rubric: dict[str, list[rule_id]]
    tri_state_summary: dict[str, int]
```

Confidence model documented in scoring-rubric; TLS-1.3-cert invisibility lowers `sub_x509` confidence to a floor; unobservable classes report `NOT-OBSERVABLE`.

## Module 5 — ML / Anomaly

```python
@dataclass
class MlConfig:
    isolation_forest: bool = True
    autoencoder: bool = True
    nonce_reuse: bool = True
    randomness_entropy: bool = True
    ja3s_drift: bool = True
    gbdt_model: Path | None = None     # weak-vs-strong, trained in lab, shipped with package

def ml_sweep(flows: list[FlowRecord], cfg: MlConfig, mx_context: dict) -> list[MLFlag]: ...
```

Rule: ML flags never mutate deterministic score absent a rule-engine-anticipated cross-signal (architecture doc §4).

## Module 6 — Downgrade Radar

```python
def radar(flows: list[FlowRecord], elephant: ElephantSeed) -> list[RadarEvent]:
    # signals: ADVERTISED_UNUSED, NO_TLS_FOLLOW, REJECT_454, CERT_CT_DRIFT, JA3S_MULTIPLICITY
    # returns p_strip per signal + merged posterior per MX
```

`p_strip` = Bayesian update with prior from ecosystem baselines (IMC'15 20%?). Prior constants pinned in `config.py` with source citation.

## Module 7 — Delivery Graph

```python
def build_graph(flows: list[FlowRecord], peer_scores: dict[str, PostureScore]) -> GraphModel:
    # nodes = enterprise + peers; edges with mail_count/bytes + weakest-hop flag
def histogram_exposure(graph: GraphModel) -> list[WeakestHop]: ...
```

## Module 8 — Enforcement Consistency

```python
def enforce_check(mx: str, flows: list[FlowRecord]) -> EnforcementRow:
    # DNS reads (MX/A/TXT MTA-STS/DANE/TLS-RPT/DNSSEC) X observed_plaintext_ratio
```
DNS lookups are passive record reads (dns.getaddrinfo / dnspython TXT) — this is the ONLY network operation in the whole system.

## Module 9 — Evidence Store

```python
def insert_session(session: ...) -> str
def add_findings(f: list[Finding])
def evidence_chain(finding_id) -> EvidenceChain   # flow_id/packet_no/byte_offset/rule_id
def commit_report(session_id, hash256)            # housekeep + seal
```

## Module 10 — Reports + Dashboard API

```python
def render_json(session_id) -> dict
def render_html(session_id) -> str
def render_pdf(session_id, out) -> Path            # WeasyPrint
def remediation_playbook(session_id, mx) -> dict   # Ollama local LLM, gated by findings/rule-ids
```

Frontend consumes REST (apis doc) + WebSocket for live. No direct DB access from frontend.

---

## Cross-module invariants
1. Every module is a pure function of its inputs + `package_ver` (no hidden clock/state) → reproducibility.
2. Modules 3–8 only write via Module 9.
3. Any module may emit `warning`s, stored on the session; warnings never change scores, only confidence wording.