-- SIH26159 SecureMailScope — SQLite Evidence Store Schema (docs/01-schema.md §3)

CREATE TABLE IF NOT EXISTS capture_sessions (
  id            TEXT PRIMARY KEY,
  source_file   TEXT NOT NULL,
  started_at    TEXT,
  ended_at      TEXT,
  flow_count    INTEGER DEFAULT 0,
  package_ver   TEXT NOT NULL,
  report_hash   TEXT,
  ingested_at   TEXT
);

CREATE TABLE IF NOT EXISTS flows (
  id             TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  server_ip      TEXT,
  server_port    INTEGER,
  mx_domain      TEXT,
  service        TEXT,
  starttls_category TEXT,
  tls_json       TEXT,
  x509_json      TEXT,
  features_json  TEXT,
  entropy_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_mx  ON flows(mx_domain);
CREATE INDEX IF NOT EXISTS idx_flows_svc ON flows(service);

CREATE TABLE IF NOT EXISTS findings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  flow_id        TEXT NOT NULL,
  module         TEXT,
  rule_id        TEXT NOT NULL,
  state          TEXT,
  severity       TEXT,
  cvss           REAL,
  cwe            TEXT,
  packet_no      INTEGER,
  byte_offset    TEXT,
  tls_record_idx INTEGER,
  evidence_json  TEXT,
  confidence     REAL,
  clause         TEXT,
  title          TEXT,
  summary        TEXT,
  created_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);

CREATE TABLE IF NOT EXISTS scores (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  mx_domain      TEXT NOT NULL,
  service        TEXT NOT NULL,
  posture_index  REAL NOT NULL,
  ci_low         REAL NOT NULL,
  ci_high        REAL NOT NULL,
  grade          TEXT NOT NULL,
  sub_scores_json TEXT NOT NULL,
  rubric_json    TEXT NOT NULL,
  tri_state_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS radar_events (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  mx_domain      TEXT NOT NULL,
  signal         TEXT NOT NULL,
  p_strip        REAL NOT NULL,
  posterior      REAL NOT NULL,
  evidence_json  TEXT
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  source_node    TEXT NOT NULL,
  target_node    TEXT NOT NULL,
  volume         INTEGER NOT NULL,
  percentage     REAL NOT NULL,
  status         TEXT NOT NULL,
  is_weakest     BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS enforcement (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id     TEXT NOT NULL REFERENCES capture_sessions(id),
  domain         TEXT NOT NULL,
  mta_sts_mode   TEXT,
  dane_tlsa      TEXT,
  tls_rpt        BOOLEAN,
  plaintext_ratio REAL,
  verdict        TEXT NOT NULL
);
