# SIH26159 SecureMailScope — 01. Data & Schema

Design-only. SQLite 3. Table names, column names, and meanings are fixed before coding.

## 1. Per-flow JSON (ingest output, also the storage unit)

```jsonc
{
  "capture_session_id": "uuid",
  "file": "weak-smtp.pcap",
  "flow_id": "tcp|192.0.2.10:41000->192.0.2.22:25|0",
  "server_ip": "192.0.2.22", "server_port": 25,
  "client_ip": "192.0.2.10",
  "mx_domain": "mail.lab.example",       // resolved from SNI/PTR/extract
  "service": "smtp",                     // smtp|imap|pop3|implicit-smtp|implicit-imap|implicit-pop3
  "starttls_category": "upgraded",       // see §2
  "tls": {
    "observed_version": "TLSv1.2",
    "client_hello_max": "TLSv1.2",
    "cipher_suite_iana": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "key_exchange": "ECDHE_RSA", "pfs": true,
    "aead": true, "encrypt_then_mac": null,
    "client_random": "hex32", "server_random": "hex32",
    "nonce_reuse": false,
    "ja3s": "...", "ja4s": "...", "jarm": "...",
    "session_resumption": false, "fallback_scsv": false,
    "renegotiation_info": false, "extended_master_secret": true,
    "compression": false, "alpn": null
  },
  "x509": {
    "subject_cn": "mail.lab.example", "san": ["mail.lab.example"],
    "issuer": "Lab Root CA",
    "not_before": "2026-01-01", "not_after": "2027-01-01",
    "rsa_modulus_bits": 2048, "sig_algo": "sha256WithRSAEncryption",
    "ecdsa_curve": null, "scts": 0,
    "chain": ["certDERb64...", "inter...", "root..."],
    "chain_len": 3,
    "validated": false, "validation_error": "HOSTNAME_MISMATCH" // RFC 5280 §6
  },
  "features": [/* 25 numeric/string, ordered as Appendix A of research doc */],
  "entropy": {"client_random_hist": 0.83, "server_random_hist": 0.81, "client_random_repeat_bucket": null}
}
```

## 2. STARTTLS transition categories (per service grammar)

```
advertised             EHLO lists STARTTLS, session upgraded with TLS records following
advertised_unused      EHLO advertises, session completes plaintext
stripped               STARTTLS verb seen, 454/"Must issue STARTTLS" absent, then plaintext continues
injected               TLS 1.2+ record *before* any STARTTLS negotiation (possible injection)
implicit               no STARTTLS at all (465/993/995 implicit TLS, RFC 8314)
none_clear             no TLS capability anywhere on a mail port
```

## 3. SQLite schema (evidence store)

```sql
CREATE TABLE capture_sessions (
  id            TEXT PRIMARY KEY,              -- uuid
  source_file   TEXT NOT NULL,
  started_at    TEXT, ended_at TEXT,
  flow_count    INTEGER,
  package_ver   TEXT NOT NULL,                 -- reproducibility pin
  report_hash   TEXT,                          -- SHA-256, set by reports
  ingested_at   TEXT
);

CREATE TABLE flows (
  id             TEXT PRIMARY KEY,             -- flow_id
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  server_ip      TEXT, server_port INTEGER, mx_domain TEXT,
  service        TEXT, starttls_category TEXT,
  tls_json       TEXT,                         -- §1 `tls`
  x509_json      TEXT,                         -- §1 `x509`
  features_json  TEXT,                         -- 25-vector
  entropy_json   TEXT
) ;
CREATE INDEX idx_flows_mx  ON flows(mx_domain);
CREATE INDEX idx_flows_svc ON flows(service);

CREATE TABLE findings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT    NOT NULL,
  flow_id        TEXT    NOT NULL,
  module         TEXT,                          -- rules|radar|graph|enforce|decay|ml
  rule_id        TEXT    NOT NULL,              -- SMS-<CAT>-<NNN> (scoring-rubric doc)
  state          TEXT,                          -- SECURE|VULNERABLE|NOT-OBSERVABLE
  severity       TEXT,                          -- info|low|medium|high|critical
  cvss           TEXT,                          -- vector string
  cwe            TEXT,
  packet_no      INTEGER, byte_offset INTEGER, tls_record_idx INTEGER,
  evidence_json  TEXT,                          -- per-finding specifics
  confidence     REAL,                          -- 0..1
  created_at     TEXT
) ;
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_sev  ON findings(severity);

CREATE TABLE scores (                           -- one row per service-MX
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL,
  mx_domain      TEXT NOT NULL,
  service        TEXT NOT NULL,
  sub_protocol REAL, sub_cipher REAL, sub_key REAL,
  sub_x509     REAL, sub_dns    REAL, sub_enforce REAL,
  posture_index REAL NOT NULL,                  -- 0..100
  confidence_low REAL, confidence_high REAL,    -- CI band
  rubric_json   TEXT,                           -- which rules fired per bucket
  UNIQUE(session_id, mx_domain, service)
) ;

CREATE TABLE radar_events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  mx_domain TEXT NOT NULL,
  signal    TEXT,      -- ADVERTISED_UNUSED|NO_TLS_FOLLOW|REJECT_454|CERT_CT_DRIFT|JA3S_MULTIPLICITY
  p_strip   REAL,      -- posterior probability
  evidence_json TEXT
) ;

CREATE TABLE graph_edges (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  from_mx   TEXT NOT NULL,                      -- enterprise egress
  to_mx     TEXT NOT NULL,                      -- peer
  mail_count INTEGER, bytes INTEGER,
  peer_score REAL, peer_confidence REAL,
  weakest   INTEGER,                            -- flag
  traffic_weight REAL
) ;

CREATE TABLE enforcement (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id   TEXT NOT NULL,
  mx_domain    TEXT NOT NULL,
  mta_sts_policy TEXT,      -- none|testing|enforce
  mta_sts_valid INTEGER,
  dane_tlsa     TEXT,       -- none|valid|invalid
  tls_rpt       INTEGER,
  dnssec        INTEGER,
  observed_plaintext_ratio REAL,   -- counter-evidence
  verdict       TEXT,             -- CONSISTENT|VIOLATION|UNOBSERVED
  rule_id       TEXT
) ;

CREATE TABLE decay_series (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  mx_domain  TEXT NOT NULL,
  window_start TEXT, window_end TEXT,
  posture_index REAL, confidence REAL,
  changepoint INTEGER,             -- 1 if change-point fired at window boundary
  baseline_ja3s_hash TEXT
) ;

CREATE TABLE ml_flags (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    TEXT NOT NULL,
  flow_id       TEXT,
  detector      TEXT,       -- isolation_forest|autoencoder|nonce_reuse|randomness|ja3s_drift
  anomaly_score REAL, differential REAL,
  shap_json     TEXT,       -- top contributing features
  note          TEXT        -- e.g. "flag does NOT change deterministic score: no cross-signal"
) ;
```

## 4. Naming / invariants

- `from_mx` = the MX of the capturing enterprise; `to_mx` = peer it delivered to (reversed lookups of server_ip via captured DNS or configured mapping stored in a `peers` table).
- `confidence` live in `[0,1]`; sub-confidences derived per §Addendum in scoring-rubric doc.
- Never store plaintext SMTP bodies; `tls_json`/`x509_json` only.
- Migration policy: single `schema.sql`; `package_ver` column gates reproducibility hashes — a schema change bumps version and re-hashes.