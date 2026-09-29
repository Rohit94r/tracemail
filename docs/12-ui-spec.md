# SIH26159 SecureMailScope — 12. UI Specification (the 9 screens)

> **For the build agent:** one sidebar, 9 tabs. Screens 1–5 are **core (MUST ship)**; 6–9 are **stretch**. Every screen lists: route, purpose, component tree, the exact API it calls, and its states (loading / empty / error). Copy the labels verbatim — they are part of the demo.

---

## 0. App shell (wraps all 9 screens)

```
<AppShell>
├─ <Header>
│   ├─ brand: "SecureMailScope"  + offline badge  ← usePoll('/api/v1/health')
│   ├─ session selector (active session id)      ← GET /api/v1/captures
│   └─ package_ver chip (reproducibility pin)   ← from any score payload
├─ <Sidebar>  9 tabs, grouped:
│   ├─ CORE:   1 Ingest · 2 Posture · 3 Graph · 4 Findings · 5 Reports
│   └─ STRETCH: 6 Replay · 7 Ask · 8 Attack Lens · 9 Integrity
└─ <Outlet/>
```

**Offline badge** — the single most load-bearing UI element for the "air-gapped" claim:
- `ONLINE · DNS ENRICHED` (green) when `/api/v1/health.net` = `online`
- `OFFLINE · METADATA ONLY` (amber) when `offline` — never hide it, it is a feature.

`GET /api/v1/health` → `{ status, net: "online"|"offline", dns_ok: bool, package_ver, llm: "ready"|"absent", db_ok }`

---

## 1. Ingest — `/` · **CORE** · FR-1,2,4,5,6

**Purpose:** get a capture in and watch it score. This is screen #1 of the demo.

```
<IngestScreen>
├─ <Dropzone>            drag .pcap/.pcapng  |  click to browse  |  size cap 2GB
├─ <FolderMode>          path input (allow-list) + "watch" toggle
├─ <LiveBadge>           WS connected/disconnected  ← /ws/live
├─ <PipelineProgress>    stage chips: Enqueued→Parsing→Features→Rules→ML→Radar→
│                        Graph→Enforce→Reports→Done, each with % and spinner
├─ <SessionResult>       on done: {session_id, flow_count, warnings[], report_hash}
├─ <WarningList>         amber, non-blocking (FR-6)
└─ <SessionTable>        past sessions: id, file, started, flows, hash (click→Posture)
```

- **API:** `POST /captures/upload` · `POST /captures/from-folder` · `GET /captures` · `GET /captures/{id}/status` · `WS /ws/live`
- **States:** empty (dropzone pulse) · uploading (progress) · processing (stage chips) · done (jump-to-findings CTA) · error (400/413 with the API's `error.code`)
- **The one-click handoff:** on `done`, show **"View findings →"** which routes to `/findings?session_id=…` (this is the 3-click demo path from PRD §3).

---

## 2. Posture Dashboard — `/posture` · **CORE** · FR-20..24

**Purpose:** the verdict. Score + CI + grade, per MX, with honesty about confidence.

```
<PostureScreen>
├─ <VerdictHero>   big:  "58"  [44–69]  · Grade D  · ⚠ low confidence
│                   reason chip: "chain not-observable (TLS1.3)"  ← click → tooltip
├─ <MxHeatmap>     rows=MX, cols=6 sub-scores (Proto/Ciph/Key/X509/DNS/Enforce),
│                   cell color = score, hatch pattern = NOT-OBSERVABLE (never solid green)
├─ <ScoreCards>    per-MX: index, CI, grade, tri-state counts {SECURE,VULN,NOT-OBS},
│                   flow count  → click routes to /findings?mx=
├─ <DecayTimeline>  line chart, posture over windows, changepoint markers   (stretch, S)
└─ <EnforcementPanel> per domain: MTA-STS mode, DANE TLSA, TLS-RPT, DNSSEC,
                        observed_plaintext_ratio, verdict badge (CONSISTENT/VIOLATION/UNOBSERVED)
```

- **API:** `GET /mx` · `GET /mx/{mx}/posture` · `GET /mx/{mx}/history` · enforcement rows
- **Render rule (critical):** the hero is **never a bare number** — always `score [low–high] · grade · confidence-label`. A `VIOLATION` badge must be visually louder than any score.
- **States:** no session (prompt to Ingest) · loading · mixed-confidence (show widest CI first) · error.

---

## 3. Delivery Graph — `/graph` · **CORE** · FR-25..27

**Purpose:** "your MXs are A-grade, but mail leaks through these peers."

```
<GraphScreen>
├─ <DeliveryGraph>   force-directed: center = your MX(s); leaves = peers.
│                    edge width ∝ mail_count; edge color = peer grade;
│                    weakest-hop edges: red dashed + ⚠ marker
├─ <WeakestHopList>  ranked: "mail.peerX — grade E — 1,204 msgs (34% of outbound)"
└─ <ExposureHistogram> distribution of exposure across hops
```

- **API:** `GET /graph/{session_id}`
- **States:** empty (no edges) · single-node (no peers yet) · loaded. Click a peer → its Posture card.

---

## 4. Findings Explorer — `/findings` · **CORE** · FR-28..32

**Purpose:** risk-ranked truth with drillable evidence. The screen the demo lingers on.

```
<FindingsScreen>
├─ <FilterBar>    severity | rule_id | module | MX | service | state   (chips, multi-select)
├─ <FindingsTable>  [severity][rule_id][MX][service][CVSS][CWE][confidence][state][⋯]
│                    sortable by severity/CVSS/confidence; state badge tri-color
└─ <EvidenceDrawer>  (slides in on row click)
     ├─ provenance: flow_id · packet_no · byte_offset · tls_record_idx · rule_id
     ├─ span_hash (SHA-256)  +  "verify" link → Integrity
     ├─ decoded snippet (hex/ascii of the cited bytes)
     ├─ RFC/NIST clause the rule cites
     └─ [▶ Replay this flow]  ← routes /replay?finding=…
```

- **API:** `GET /findings?session_id=&severity=&rule_id=&mx=` · `GET /findings/{id}/chain`
- **Render rule:** `state` badge is load-bearing — `NOT-OBSERVABLE` rows are visually muted and labelled, never hidden and never green.
- **States:** no findings for filters (empty) · loaded. CSV export (S).

---

## 5. Reports — `/reports` · **CORE** · FR-33..37

**Purpose:** the artifact that leaves the tool — signed, cited, actionable.

```
<ReportsScreen>
├─ <ExportBar>   [JSON] [HTML] [PDF]   ← GET /reports/{sid}.{ext}
├─ <SealCard>     report SHA-256 + package_ver + "verify" (→ Integrity)
├─ <Playbook>     per-MX remediation ("fix now"):
│                   each recommendation line ends with (rule_id: SMS-XXX-NNN)
│                   LLM-generated via local Ollama; deterministic template fallback
├─ <Hardening>    "stay ahead": policy rollout (MTA-STS testing→enforce, DANE rollover),
│                   key rotation, CT/OCSP, PQC/CNSA-2 readiness, monitoring thresholds
└─ <ReportPreview> rendered report (score+CI, findings, radar, enforcement, provenance, seal)
```

- **API:** `GET /reports/{sid}.{json|html|pdf}` · `POST /reports/{sid}/playbook` · `GET /reports/{sid}/hash`
- **Fallback rule (must work with LLM off):** playbook renders from a deterministic template keyed on `rule_id`; the LLM only rewrites prose. If `/health.llm` = `absent`, show "template playbook (LLM unavailable)".

---

## 6. Incident Replay — `/replay` · **STRETCH** · FR-38

**Purpose:** "watch how it happened, like a video."

```
<ReplayScreen>
├─ <FlowPicker>    pick flow / arrive with ?finding=…
├─ <Timeline>      animated: TCP stream → protocol dialog → STARTTLS → TLS handshake → cert
│                  critical moments pulse red with rule_id + "why" chip
├─ <Scrubber>      play/pause · seek · speed · packet-by-packet
└─ <ExportWebM>    render to video artifact
```

- **API:** replays off `GET /findings/{id}/chain` + the evidence store's ordered events.
- **Guardrail:** shows **observed packets only**; NOT-OBSERVABLE segments are greyed + labelled, never invented.

---

## 7. Ask (RAG chat) — `/ask` · **STRETCH** · FR-39

**Purpose:** plain-language Q over the findings, grounded and cited.

```
<AskScreen>
├─ <ChatThread>    user question → grounded answer → [finding-id chips] → link to evidence
├─ <RefusalState>  if retrieval < threshold: "Not enough evidence in this capture to answer that."
└─ <SourcePanel>   the retrieved finding IDs + their rule_ids
```

- **API:** `POST /api/v1/ask` (question, session_id) → `{answer, citations:[finding_id], refused:bool}`
- **Guardrails:** every claim cites finding IDs; **must refuse** below threshold; no free-floating answers; local embeddings + local LLM only (no egress).

---

## 8. Attack Lens — `/lens` · **STRETCH** · FR-40

**Purpose:** "what's most likely next, based on what we see" — a forecast, clearly labelled.

```
<LensScreen>
├─ <ForecastList>  ranked likely-next attacks (from the 10 §4 mapping):
│                    each: attack class · likelihood (low/med/high) · confidence label
├─ <Drivers>        the exact findings that drive each forecast (click → evidence)
└─ <ForecastBanner> "FORECAST, NOT FACT — evidence-forward extrapolation" (always visible)
```

- **API:** `GET /api/v1/lens/{session_id}` → ranked `{attack, likelihood, driver_finding_ids}`
- **Guardrail:** every forecast needs ≥1 observed finding; confidence shrinks when evidence is thin; the "not fact" banner is non-dismissible.

---

## 9. Integrity — `/integrity` · **STRETCH** · FR-41

**Purpose:** prove nothing was tampered with.

```
<IntegrityScreen>
├─ <ManifestTree>   file → SHA-256 + size + package_ver (from MANIFEST.sha256)
├─ <VerifyButton>   re-walk the chain, recompute hashes, show per-node ✓/✗
└─ <TamperFlag>     if a hash mismatches, a red branch explains what changed
```

- **API:** `GET /api/v1/integrity/manifest` · `POST /api/v1/integrity/verify` · `GET /reports/{sid}/hash`

---

## Quick reference: screen → API map

| # | Screen | Route | Primary endpoints |
|---|---|---|---|
| 1 | Ingest | `/` | `POST /captures/upload`, `/from-folder`, `GET /captures`, `/status`, `WS /ws/live` |
| 2 | Posture | `/posture` | `GET /mx`, `/mx/{mx}/posture`, `/mx/{mx}/history`, enforcement |
| 3 | Graph | `/graph` | `GET /graph/{session_id}` |
| 4 | Findings | `/findings` | `GET /findings`, `/findings/{id}/chain` |
| 5 | Reports | `/reports` | `GET /reports/{sid}.{json,html,pdf}`, `/playbook`, `/hash` |
| 6 | Replay | `/replay` | `GET /findings/{id}/chain` + evidence events |
| 7 | Ask | `/ask` | `POST /api/v1/ask` |
| 8 | Lens | `/lens` | `GET /api/v1/lens/{session_id}` |
| 9 | Integrity | `/integrity` | `GET /integrity/manifest`, `POST /integrity/verify` |

> Endpoints 1–5 exist in `04-apis-events.md`. `/health`, `/ask`, `/lens`, `/integrity` are **additions** for this UI spec — add them following the same `/api/v1` namespace, error shape, and single-user (no-auth) model.

---

*Cross-refs: PRD `11-prd.md` · build order `13-agent-build-plan.md` · API `04-apis-events.md` · advanced features `10-advanced-capabilities.md`.*
