# SIH26159 SecureMailScope — 04. REST & Events API

Design-only. `backend` serves its own REST API; `frontend` never touches SQLite.

## 1. Namespace

```
/api/v1/captures          # upload / list / session control
/api/v1/mx                # posture store reads
/api/v1/graph             # delivery graph model
/api/v1/findings          # explorer + evidence chain
/api/v1/reports           # JSON/PDF/HTML + playbooks
/ws/live                  # realtime chunk feed (WebSocket)
```

## 2. Endpoints

### Captures
```
POST  /api/v1/captures/upload              multipart file(s) → {session_id, flow_count, warnings}
POST  /api/v1/captures/from-folder         {path} (allow-list: lab/live, corpus/scenarios) → {session_id}
GET   /api/v1/captures                     list sessions (id, file, counts, report_hash)
GET   /api/v1/captures/{id}                session detail incl. warnings
GET   /api/v1/captures/{id}/status         {stage, pct, eta}  (ingest→features→rules→ml→radar→graph→enforce→reports)
POST  /api/v1/captures/import-zeek         {ssl_log_path, x509_log_path, pcap_path?}
```

### Scores & MX
```
GET  /api/v1/mx/{mx}/posture              → PostureScore (index, ci, rubric_json, tri_state)
GET  /api/v1/mx/{mx}/history              → decay_series rows
GET  /api/v1/mx                          → distinct MXs w/ aggregate score, groupable by service
```

### Graph
```
GET /api/v1/graph/{session_id}            → nodes+edges+weakest-hop+histogram_exposure
```

### Findings / evidence
```
GET   /api/v1/findings?session_id=&severity=&rule_id=&mx=
GET   /api/v1/findings/{finding_id}/chain → {flow_id, packet_no, byte_offset, tls_record_idx, rule_id, span_hash}
```

### Reports
```
GET /api/v1/reports/{session_id}.json
GET /api/v1/reports/{session_id}.html
GET /api/v1/reports/{session_id}.pdf
POST /api/v1/reports/{session_id}/playbook   {mx} → JSON remediation plan (LLM, gated)
GET /api/v1/reports/{session_id}/hash        → {sha256, package_ver}
```

### Live feed
```
WS /ws/live?session_group=preferred
→ server pushes {type: "chunk", file, session_id, starttls_category_counts, posture: {mx:[{index,ci}]}}
→ client renders into Ingest + Posture Dashboard screens live
```

## 3. Event model (status propagation)

Stage enum (single pipeline): `enqueued → parsing → features → rules → ml → radar → graph → enforce → reports → done`. Emitted as `{type:"stage", stage, pct}` over the REST cancel token and `/ws/live` opportunistically.

## 4. Errors

- 400 bad capture (unsupported codec/empty) → `{error: {code, message, warnings}}` — ingest module still returns warnings so judge sees graceful degradation.
- 404 unknown session/finding; 409 session already processing (re-upload); 413 size cap (default 2 GB).
- 429 not used (single-user local).

## 5. Frontend consumption (core screens 1–5)

The dashboard has **9 screens** total (5 core here + 4 stretch). This table covers the **core five**; the stretch screens (6 Incident Replay, 7 Ask, 8 Attack Lens, 9 Integrity) add `/ask`, `/lens`, `/integrity` and consume the same endpoints — see `12-ui-spec.md` §Quick reference.

| Screen | Route | Endpoints |
|---|---|---|
| 1 Ingest | `/` | POST upload / from-folder, GET /captures, GET /status, WS /ws/live |
| 2 Posture Dashboard | `/posture` | GET /mx/{mx}/posture, /mx, /mx/{mx}/history, enforcement rows |
| 3 Delivery Graph | `/graph` | GET /graph/{sid} |
| 4 Findings Explorer | `/findings` | GET /findings, /findings/{id}/chain |
| 5 Reports | `/reports` | GET /reports/{sid}.{json,html,pdf}, /playbook, /hash |

### 5.1 Additions required by the 9-screen UI (`12-ui-spec.md`)

Same `/api/v1` namespace, same error shape (§4), single-user / no-auth:

```
GET  /api/v1/health                        → {status, net:"online"|"offline", dns_ok, package_ver, llm:"ready"|"absent", db_ok}
GET  /api/v1/enforcement?session_id=       → EnforcementRow[] (docs/01 §3 `enforcement`)
POST /api/v1/ask                          {question, session_id} → {answer, citations:[finding_id], refused:bool}
GET  /api/v1/lens/{session_id}            → [{attack, likelihood, confidence, driver_finding_ids[]}]  (labeled forecast-not-fact)
GET  /api/v1/integrity/manifest           → [{file, sha256, size, package_ver}]
POST /api/v1/integrity/verify             → [{file, expected, actual, ok, tampered_branch?}]
GET  /api/v1/replay/{finding_id}          → ordered replay events (observed only; NOT-OBSERVABLE flagged)
```

`/health` backs the offline badge and gates the LLM-fallback path; the others back stretch screens 6–9.