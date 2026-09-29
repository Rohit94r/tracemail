# SIH26159 SecureMailScope — 00. Architecture

Design-only. No code yet. Follows `../SIH26159-SecureMailScope-Research.md` §8.3 pipeline.

## 1. Physical model

```
┌─ OFFLINE LAPTOP (demo/ship target, zero-cloud) ──────────────────────┐
│  backend/   FastAPI analysis engine (Python 3.12)                    │
│    ingest/  features/  rules/  ml/  radar/  graph/  enforce/         │
│    decay/   evidence/  reports/  api/                                │
│  frontend/  Next.js dashboard (5 screens) → browser                  │
│  SQLite  evidence store + span hashes                                │
│  Ollama    local LLM → remediation playbooks (optional, offline)     │
└──────────────────────────────────────────────────────────────────────┘
          ▲ ingest source
┌─────────┴───────────────────────────────────────┐
│ a) uploaded PCAP file/dir  (judge flow)         │
│ b) lab/live/ capture chunks  (VPS agent sink)   │
│ c) existing tcpdump/Zeek outputs (import)       │
└─────────────────────────────────────────────────┘
```

- Two processes: `backend` (FastAPI, owns SQLite) and `frontend` (Next.js, talks to backend via REST + WebSocket).
- Everything runs under `docker compose up` with all images pre-pulled; fully functional with Wi-Fi disabled.
- The only network reads anywhere: **DNS** (MX/MTA-STS/TXT/DANE TLSA records) in the enforcement module. This is record lookup, not server scanning — PS-literal.

## 2. Module dependency graph

```
 ingest ─▶ features ─▶ rules ─▶ score ─┐
     │          │         │            ├─▶ evidence ─▶ reports (JSON/PDF/HTML + LLM)
     │          └──▶ ml   ┘            │
     │          └──▶ radar ────────────┤
     └────────────▶ graph ─────────────┤
                    enforce ───────────┤
                    decay ─────────────┘
                          (all write into evidence store)
```

Feeding order per capture: `ingest → features → {rules, ml, radar}` → parallel → `score` (rule sub-scores + radar penalties + ML anomaly cross-signals) → `evidence` persist → `reports` render.

## 3. Processing semantics

- **Batch RPC per capture artist**: each capture becomes a `CaptureSession` (unique id). Modules run deterministically and idempotently on its per-flow JSON.
- **Per-flow records** carry `flow_id` (5-tuple key), `mx_domain`, `service` (smtp/imap/pop3/implicit-smtp/implicit-imap/implicit-pop3), `starttls` transition category, plus the 25-feature vector (Appendix A of research doc). `posture_score` is per-SERVICE per-MX; aggregated per-MX and per-enterprise.
- **Realtime** (`lab/live/`): new chunks are appended as new sessions; time-series tables derive from same deterministic pipeline (no double engine).

## 4. Cross-cutting rules

1. **Deterministic-first**: score = rule engine output. ML may only *annotate/rank*, never mutate the score, unless a cross-signal (≥2 independent signals) triggers an explicit flag that the rule engine already anticipated (`POSTURE-DECAY`, `RADAR-*`).
2. **Tri-state**: any evidence class that cannot be observed (e.g., cert chain under TLS 1.3) is assigned `NOT-OBSERVABLE`, never "clean". Confidence bounds shrink accordingly.
3. **Provenance**: every finding row stores `(capture_session_id, flow_id, packet_no, byte_offset, tls_record_idx, rule_id)`. Report content-hash = SHA-256 over serialized findings + evidence spans.
4. **idempotence**: given the same capture + same package version, the report hash must be reproducible (enforced by `make verify` regression harness — corpus §5).
5. **No credentials, no content**: engine touches handshake/cipher/cert/DNS metadata only.

## 5. Non-functional targets (for build)

- Ingest ≤ 1.5× read time of tshark on a 1 GB capture (single-pass, no per-record DB write per packet — batch flush).
- Score recompute per service-MX < 500 ms for 10k flows.
- Full judge flow (upload → report PDF) < 90 s on laptop.
- Report reproducibility: `make verify` re-computes identical SHA-256 for the shipped corpus.