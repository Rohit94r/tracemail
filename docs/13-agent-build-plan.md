# SIH26159 SecureMailScope — 13. Agent Build Plan (execution playbook)

> **For the build agent (or AI coding assistant):** this is your task list. Read `AGENTS.md` first, then this file, then the design contracts it references. Work **top to bottom**. Each task has an ID, dependencies, and an **acceptance check you must be able to run**. Do not start a task whose deps aren't green. When a task's acceptance check can't run (e.g. no pcap yet), mark it BLOCKED and move on — never fake a pass.

---

## 0. Ground rules (non-negotiable)

1. **Design contracts win.** `docs/00`–`05` fix the schema, rule IDs, module signatures, and API shape. Don't invent new fields; extend via a new doc if truly needed.
2. **Deterministic-first.** Score = rule engine only. ML ranks/flags; it never mutates a score.
3. **Tri-state honesty.** Unobservable ≠ clean. `NOT-OBSERVABLE` everywhere it applies.
4. **Passive.** No packets to mail servers. Only network op = DNS record reads. If your code would connect to a mail host, it's wrong.
5. **Offline-first.** `make up` works with no internet; the only optional enrichment is DNS.
6. **Reproducible.** Same capture + same `package_ver` ⇒ same report SHA-256. `make verify` proves it.
7. **Metadata only.** Never store plaintext SMTP bodies, keys, or credentials.
8. **No secrets in git.** `.env.local`, `*.key`, `*.pem` are gitignored.

---

## 1. Repository scaffold (Phase P0)

```
securemailscope/
├─ backend/
│  ├─ pyproject.toml            # deps: fastapi, uvicorn, pyshark, scapy, cryptography,
│  │                            #       pydantic, scikit-learn, xgboost, shap, jinja2, weasyprint, dnspython
│  ├─ app/
│  │  ├─ main.py                # FastAPI app, mounts /api/v1, /ws/live
│  │  ├─ config.py              # pinned radar priors + citations (docs/03 §4)
│  │  ├─ db.py                  # sqlite, schema.sql loader, migrations gated by package_ver
│  │  ├─ api/                   # routers: captures, mx, graph, findings, reports, health, ask, lens, integrity
│  │  └─ modules/               # ingest, features, rules, ml, radar, graph, enforce, decay, evidence, reports  (docs/02)
│  └─ tests/
├─ frontend/
│  ├─ package.json              # next, react, typescript, recharts/d3, ws client
│  └─ app/                      # 9 screens per docs/12-ui-spec.md
├─ corpus/
│  ├─ scenarios/                # 5 labeled pcaps + oracle (testssl.sh) output
│  ├─ live/                     # runtime capture chunks (gitignored)
│  └─ expected/                 # expected report-hash + posture range per scenario
├─ lab/                         # capture agent + docker (docs/05)
├─ docs/                        # these design docs (read-only for build agent)
├─ Makefile                     # up, down, verify, demo, test, lint
├─ docker-compose.yml
└─ README.md
```

**Makefile targets (must exist):**

| Target | What it does |
|---|---|
| `make up` | build + start backend+frontend (pre-pulled images) |
| `make down` | stop |
| `make test` | backend unit tests |
| `make verify` | run pipeline over `corpus/scenarios`, recompute hashes, compare to `corpus/expected`, **exit 0/1** |
| `make demo` | load a scenario pcap end-to-end and print the posture line |
| `make lint` | ruff / eslint |

**`.gitignore` must include:** `.env*`, `corpus/live/`, `*.key`, `*.pem`, `node_modules`, `__pycache__`, `.next`.

### Task P0-1 — Scaffold
- **Deps:** none
- **Do:** create the tree above; `pyproject.toml`; `docker-compose.yml` (backend+frontend); `Makefile`; `.gitignore`; `backend/app/main.py` returning `{"status":"ok"}` at `/api/v1/health`; a Next.js shell that renders the sidebar with 9 tab names.
- **Accept:** `make up` → `curl localhost:8000/api/v1/health` = `{"status":"ok"}`; browser shows 9 tabs.

---

## 2. Core engine (Phase P1) — no UI polish

Follow the module dependency graph in `docs/00` §2 and the signatures in `docs/02`. Feeding order per capture:
`ingest → features → {rules, ml, radar} (parallel) → score → evidence persist → reports`.

### Task P1-1 — Ingest/Parse
- **Deps:** P0-1
- **Do:** `parse_capture()` per `docs/02` M1. tshark via pyshark primary, scapy fallback. Implement the **6-class STARTTLS state machine** (`docs/01` §2) for smtp/imap/pop3. Decode X.509 via `cryptography` (subject, SAN, issuer, validity, key bits, sig algo, chain).
- **Accept:** `python -m app.modules.ingest corpus/scenarios/stripped.pcap` returns flows with correct `starttls_category`; warnings array populated on truncation.

### Task P1-2 — Feature layer
- **Deps:** P1-1
- **Do:** `build_features()` → 25-vector, ja3s/ja4s, cipher-family/FS enums, client_random entropy + repeat bucket.
- **Accept:** feature vector length == 25 for every flow; ja3s matches a known-good value for a fixture.

### Task P1-3 — Rule engine
- **Deps:** P1-2
- **Do:** `evaluate_rules()` per `docs/02` M3. Implement the **rule catalog in `docs/03` §3** (SMS-PROTO/CIPH/KEY/X509/DNS/ENF/RADAR/MLNA-*) with exact severities/CWEs/CVSS. Each finding carries `rule_id → clause → state → severity → cvss → cwe`.
- **Accept:** on a `stripped.pcap` fixture, `SMS-ENF-002` (stripped) fires; on a `weak-cipher.pcap`, `SMS-CIPH-001` fires. Unit test asserts rule IDs.

### Task P1-4 — Posture scoring (confidence-bounded)
- **Deps:** P1-3
- **Do:** `compute_posture()` per `docs/02` M4 + `docs/03` §1–2. 6 weighted sub-scores (20/25/15/15/10/15) → index; grade A–E; 95% CI from sub-confidences; x509 conf floor 0.15 under TLS-1.3; tri-state counts.
- **Accept:** returns `index, ci_low, ci_high, rubric, tri_state_summary`; a fixture with an unobservable chain yields **widened** CI and a `NOT-OBSERVABLE` x509 state (unit test).

### Task P1-5 — Evidence store
- **Deps:** P1-3
- **Do:** `docs/01` §3 SQLite schema (verbatim). `insert_session`, `add_findings`, `evidence_chain`, `commit_report`. Report hash = SHA-256 over serialized findings+evidence.
- **Accept:** `evidence_chain(finding_id)` returns the full provenance tuple; re-hashing the same session twice yields the same hash.

### Task P1-6 — Reports (JSON/HTML/PDF)
- **Deps:** P1-4, P1-5
- **Do:** `render_json`, `render_html`, `render_pdf` (WeasyPrint) per `docs/02` M10. Report includes score+CI, findings, provenance, and the **report seal** in the header.
- **Accept:** `make demo` on one fixture prints `Posture NN [lo–hi] · Grade X`; PDF contains the SHA-256 seal string.

### Task P1-7 — CLI demo path
- **Deps:** P1-6
- **Do:** a `python -m app.cli score <pcap>` that runs the full pipeline headless and prints the posture line + top-5 findings.
- **Accept:** runs on a scenario pcap in <90 s; exit 0.

---

## 3. MVP UI (Phase P2) — screens 1–5

Screens per `docs/12-ui-spec.md`. Wire frontend to `/api/v1` (extend the routers from `04`). **The demo path is the priority:** Ingest → done → "View findings" → evidence drawer.

### Task P2-1 — App shell + 9-tab sidebar + offline badge
- **Deps:** P0-1
- **Do:** Next.js shell; 9 routes registered (5 core enabled, 4 stretch show a "stretch" chip); header with offline badge (poll `/health`), session selector, package_ver chip.
- **Accept:** all 9 routes resolve (stretch render a "coming in P5" placeholder); badge flips to `OFFLINE · METADATA ONLY` when you block the network.

### Task P2-2 — Ingest screen (S1)
- **Deps:** P1-7, P2-1
- **Do:** dropzone, folder mode, pipeline progress chips (stage enum from `04` §3), warnings, session table, "View findings →" CTA.
- **Accept:** drop `stripped.pcap` → progress chips advance → result shows session_id/flow_count/hash → CTA routes to `/findings`.

### Task P2-3 — Posture screen (S2)
- **Deps:** P1-4, P2-1
- **Do:** VerdictHero (score+CI+grade+confidence), MX×service heatmap (hatch for NOT-OBSERVABLE), score cards, enforcement panel.
- **Accept:** hero renders `NN [lo–hi] · Grade · conf`; an unobservable sub-score is hatched/greyed, not green.

### Task P2-4 — Graph screen (S3)
- **Deps:** P1-5(P5 graph), P2-1
- **Do:** force graph (enterprise center, peers), edge width=traffic, color=grade, weakest-hop red dashed, weakest-hop list.
- **Accept:** a fixture with a weak peer shows ≥1 weakest hop highlighted + list row.

### Task P2-5 — Findings screen (S4) — **the money screen**
- **Deps:** P1-5, P2-1
- **Do:** filter bar, risk-ranked sortable table, evidence drawer (provenance tuple + span_hash + decoded snippet + clause + Replay button).
- **Accept:** on `stripped.pcap`, ≤3 clicks from Ingest-done to seeing `SMS-ENF-002` with packet#, byte-offset, rule-ID visible in the drawer.

### Task P2-6 — Reports screen (S5) — playbook fallback
- **Deps:** P1-6, P2-1
- **Do:** export bar (JSON/HTML/PDF), seal card, **deterministic template playbook** keyed on rule_id (LLM later), hardening section.
- **Accept:** PDF downloads and shows the seal; playbook renders with LLM disabled and every line ends `(rule_id: …)`.

### Task P2-7 — WebSocket live
- **Deps:** P2-2
- **Do:** `/ws/live` pushes `{type:"chunk"|"stage", …}` per `04`; Ingest + Posture update live.
- **Accept:** a new chunk in `lab/live/` appears on the dashboard without reload.

**P2 gate (PRD §6 criteria 1–4):** demo path green; hero shows CI; graph flags a weak hop; PDF shows seal.

---

## 4. ML + radar + verify (Phase P3)

### Task P3-1 — ML sweep (rank/flag only)
- **Deps:** P1-3
- **Do:** `ml_sweep()` per `docs/02` M5: IsolationForest, AE, GCM-nonce reuse, entropy, JA3S drift, GBDT. Populate `ml_flags` with SHAP top features + the note "does NOT change deterministic score".
- **Accept:** a nonce-reuse fixture raises `SMS-MLNA-001`; the posture index is **unchanged** by the ML sweep (unit test asserts equality).

### Task P3-2 — Downgrade Radar
- **Deps:** P1-3
- **Do:** `radar()` per `docs/02` M6. 5 signals → Bayesian posterior per MX. Priors pinned in `config.py` with citation comments (`docs/03` §4).
- **Accept:** a high-`ADVERTISED_UNUSED` fixture yields `P(strip) > 0.5` and raises `SMS-RADAR-001`.

### Task P3-3 — Enforcement consistency
- **Deps:** P1-3
- **Do:** `enforce_check()` per `docs/02` M8. DNS (MX/TXT MTA-STS/TLSA/TLS-RPT/DNSSEC) × observed plaintext ratio → `CONSISTENT|VIOLATION|UNOBSERVED`. This is the ONLY network op — keep it isolated and disable-able for offline mode.
- **Accept:** a deliberately-misconfigured domain shows `VIOLATION`; with network off, rows degrade to `UNOBSERVED` (no crash).

### Task P3-4 — Delivery graph backend
- **Deps:** P1-4
- **Do:** `build_graph()` + `histogram_exposure()` per `docs/02` M7.
- **Accept:** `GET /graph/{sid}` returns nodes/edges/weakest-hop for the real corpus.

### Task P3-5 — Decay / change-point
- **Deps:** P1-4
- **Do:** posture time-series per MX, JA3S baseline, changepoint flag → `decay_series`.
- **Accept:** two synthetic windows with a score drop produce a changepoint marker.

### Task P3-6 — `make verify` harness + corpus
- **Deps:** P1-6, P3-2
- **Do:** `corpus/scenarios` = 5 labeled pcaps + testssl.sh oracle output; `corpus/expected` = expected report-hash + posture range per scenario. `make verify` recomputes and **fails on drift**.
- **Accept:** `make verify` exits 0 on a clean tree; exits 1 if a scenario's expected hash is tampered.

**P3 gate (criteria 5):** `make verify` green; ML proven not to alter scores.

---

## 5. Hardening + LLM (Phase P4)

### Task P4-1 — Local LLM playbooks (Ollama, gated)
- **Deps:** P1-6
- **Do:** `remediation_playbook()` calls local Ollama; **every** recommendation cites a `rule_id` and is gated on existing deterministic findings. If LLM absent → deterministic template.
- **Accept:** with LLM on, output lines end `(rule_id: …)`; with LLM off, template renders and `/health.llm` = `absent`. No network egress (verify in logs).

### Task P4-2 — Hardening / stay-ahead report section
- **Deps:** P1-6
- **Do:** per `docs/10` §5: policy rollout (MTA-STS testing→enforce, DANE rollover), key rotation, CT/OCSP, PQC/CNSA-2 readiness, monitoring thresholds. Each item maps to a rule_id or standard.
- **Accept:** hardening section renders in the report; every item cites a rule_id or RFC/NIST ref.

### Task P4-3 — Offline polish
- **Deps:** P2-*
- **Do:** audit every network call; only DNS may reach out. Add an `SMS-OFFLINE` mode flag. Pre-pull all docker images.
- **Accept:** full judge flow (upload→PDF) works with Wi-Fi off; `make up` with no internet.

### Task P4-4 — Demo assets
- **Deps:** P2-2
- **Do:** record a 1080p fallback video; export a sample signed PDF; screenshot the DNS panel + corpus stats; model card with F1.

**P4 gate (criteria 6–7):** offline green; playbook renders with LLM off.

---

## 6. Stretch (Phase P5) — screens 6–9

**Only start after P4 gate.** Each is self-contained and demoable in ~20 s.

### Task P5-1 — Incident Replay (S6)
- **Deps:** P1-5
- **Do:** animated timeline from ordered evidence events; flagged moments pulse red with rule_id + "why"; scrubber; WebM export. Observed-only; NOT-OBSERVABLE greyed.
- **Accept:** replaying the `stripped` finding animates the STARTTLS→plaintext moment; export produces a video file.

### Task P5-2 — Ask / RAG chat (S7)
- **Deps:** P1-6
- **Do:** `POST /api/v1/ask`; local embeddings (Ollama) over findings/rule catalog/evidence; **refuse** below retrieval threshold; every claim cites finding IDs; links to evidence drawer.
- **Accept:** "why is outlook's peer grade low?" returns a cited answer; a nonsense question **refuses**; no egress.

### Task P5-3 — Attack Lens (S8)
- **Deps:** P1-3, P3-2
- **Do:** `GET /api/v1/lens/{session_id}` implementing the `docs/10` §4 evidence→attack mapping; each forecast needs ≥1 observed finding; likelihood + confidence; non-dismissible "forecast, not fact" banner.
- **Accept:** a downgrade-heavy capture surfaces the top modeled next-attack with its driving findings.

### Task P5-4 — Integrity / tamper-proof (S9)
- **Deps:** P1-5
- **Do:** MANIFEST.sha256 tree; `POST /integrity/verify` re-walks hashes; tamper-flag branch on mismatch; signed git tag in release.
- **Accept:** tampering with one corpus file makes verify show a red ✗ at that node with an explanation.

---

## 7. Definition of done

- [ ] `make up` healthy; `make verify` exit 0; `make test` green; `make lint` clean.
- [ ] All PRD §6 success criteria pass on a rented laptop, offline.
- [ ] Screens 1–5 polished; stretch 6–9 either done or clean placeholders.
- [ ] No secrets committed; `.gitignore` correct; `package_ver` pinned; release tagged.
- [ ] Every requirement `FR-1..45` implemented or explicitly marked cut with a reason in the PR.

---

*Cross-refs: PRD `11-prd.md` · UI `12-ui-spec.md` · architecture `00` · schema `01` · modules `02` · rubric `03` · API `04` · lab `05` · usage `09` · advanced `10` · entry point `AGENTS.md`.*
