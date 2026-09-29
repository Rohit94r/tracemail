# SIH26159 SecureMailScope — 11. Product Requirements Document (PRD)

> **For the build agent:** this PRD is the contract. If code and this doc disagree, this doc wins. Every requirement has an ID (`FR-n`) and a priority (`M` = must / `S` = should) so you can cut scope without ambiguity. Companions: `12-ui-spec.md` (what each screen shows), `13-agent-build-plan.md` (task order + acceptance criteria), `00`–`05`, `09`, `10` (design contracts).

---

## 1. Product definition

**SecureMailScope** is a **self-hosted, air-gapped web application** that assesses the *cryptographic security posture* of email infrastructure from **passively captured** SMTP / IMAP / POP3 traffic.

| | |
|---|---|
| **Problem** | Email encryption is optional and actively stripped in the wild; ~30% of email certs are invalid, ~320k servers are STARTTLS-injectable, 41k actively strip, only ~1.1% enforce MTA-STS. No lightweight tool proves whether the envelope stayed sealed. |
| **Solution** | Drop in a PCAP → get a **confidence-bounded 0–100 posture score**, prioritized findings, a downgrade radar, a cross-hop delivery graph, hash-signed evidence chains, and remediation playbooks. |
| **Category** | Security posture management / passive TLS assessment (defensive, observational) |
| **Not** | Not a scanner, not a TLS breaker, not a mail host, not a SaaS |

### 1.1 Hard constraints (violating any of these is a bug, not a feature)

1. **Passive only** — no packets sent to mail servers. The *only* outbound network op in the entire system is **DNS record lookup** (MX / MTA-STS TXT / DANE TLSA / TLS-RPT) in the enforcement module.
2. **No decryption, no content, no credentials** — engine touches handshake, cipher negotiation, X.509, and DNS metadata only.
3. **Deterministic-first** — the score is rule-engine output (RFC/NIST). ML may only *rank and flag*; it must never mutate a score.
4. **Honest uncertainty** — anything not observable (e.g. X.509 chain under TLS 1.3) is `NOT-OBSERVABLE`, never "clean", and shrinks the confidence band.
5. **Offline-first** — the full judge flow (upload → report) must work with the network cable unplugged.
6. **Reproducible** — same capture + same `package_ver` ⇒ identical report SHA-256 (`make verify`).

---

## 2. Users & jobs-to-be-done

| # | User (named in PS) | JTBD | Success looks like |
|---|---|---|---|
| U1 | **SOC analyst** | "Tell me if anything in my mail path is degrading *before* it becomes an incident." | Deviation alert + decay timeline shows A→D over a window; no false "all clear". |
| U2 | **Digital-forensics examiner** | "Give me evidence I can defend in audit/court." | Every finding drilldown to `(flow, packet#, byte-offset, tls_record_idx, rule_id)` + span hash; signed PDF. |
| U3 | **Incident-response team** | "Assess a capture now without touching the possibly-compromised host." | Upload → prioritized findings in <90 s, no new access to the target. |
| U4 | **Enterprise / mail admin** | "Tell me exactly what to fix first, in my config." | Copy-paste remediation + a hardening calendar (MTA-STS→DANE, key rotation, PQC). |
| U5 | **NTRO / ministry buyer** (secondary) | "Can this run in our silo, and can we trust the number?" | Runs air-gapped on a laptop; `make verify` green; no cloud, no license. |

**Primary judge-facing persona: U1 + U3** (fastest path to "wow": drop a PCAP, get a verdict).

---

## 3. Scope — the 9 screens

The UI is a **local web dashboard: one sidebar, 9 tabs**. 5 are core (MVP), 4 are stretch (only after core is green). Full component/API detail: `12-ui-spec.md`.

| # | Tab / route | Purpose | Core? |
|---|---|---|---|
| 1 | **Ingest** `/` | Upload PCAP · point at folder · live feed · watch pipeline progress | **M** |
| 2 | **Posture Dashboard** `/posture` | Score + CI band + grade, per-MX heatmap, decay timeline, enforcement verdicts | **M** |
| 3 | **Delivery Graph** `/graph` | Your MX → peers, weakest-hop flags, traffic-weighted exposure | **M** |
| 4 | **Findings Explorer** `/findings` | Risk-ranked findings, filters, evidence-chain drawer, Replay trigger | **M** |
| 5 | **Reports** `/reports` | JSON / PDF / HTML export, report seal, remediation playbook, hardening section | **M** |
| 6 | **Incident Replay** `/replay` | Animated forensic timeline of a flow; flagged moments; WebM export | S |
| 7 | **Ask (RAG chat)** `/ask` | Grounded Q&A over findings, every answer cites finding IDs | S |
| 8 | **Attack Lens** `/lens` | Evidence-forward "likely next attack" forecast with drivers | S |
| 9 | **Integrity** `/integrity` | `MANIFEST.sha256` tree, chain verification, tamper-flag branch | S |

**Non-negotiable UX rules**
- **Screen 1 (Ingest) → Screen 4 (Findings) in ≤3 clicks** after a capture finishes. That path is the demo.
- Every posture number is rendered as `score [ci_low–ci_high] · grade · confidence label` — **never a bare number**.
- Any `NOT-OBSERVABLE` item is visually distinct (grey + label), never silently omitted and never counted as pass.
- **Offline badge** visible in the global header at all times (`ONLINE · DNS ENRICHED` / `OFFLINE · METADATA ONLY`).
- No screen requires authentication (single-user local tool). No login screen.

---

## 4. Functional requirements

Priority: **M** = must for MVP · **S** = should/stretch. Grouped by area.

### A. Ingest & session management
| ID | Req | P |
|---|---|---|
| FR-1 | Accept `.pcap` / `.pcapng` upload up to 2 GB via drag-drop and file picker; show progress % | M |
| FR-2 | Ingest from an allow-listed capture folder (lab/live, corpus/scenarios); tail new chunks as new sessions | M |
| FR-3 | Live mode: WebSocket feed of new chunks → auto-ingest → live score updates | S |
| FR-4 | Session list (id, file, started, flow count, report hash) with the ability to re-open any past session | M |
| FR-5 | Pipeline progress with stage names (`enqueued → parsing → features → rules → ml → radar → graph → enforce → reports → done`) + % | M |
| FR-6 | Warnings surfaced non-fatally (e.g. "tshark missing → scapy fallback", "pcap truncated"); warnings never change scores, only wording | M |
| FR-7 | Import Zeek `ssl.log` + `x509.log` as enrichment | S |

### B. Analysis engine (backend modules — see `02`, `03`)
| ID | Req | P |
|---|---|---|
| FR-8 | Parse flows: service ID, TCP streams, STARTTLS 6-class state machine, TLS fields, X.509 chain, 32-byte randoms | M |
| FR-9 | 25-feature vector + JA3S/JA4S + entropy per flow | M |
| FR-10 | Deterministic rule engine emitting findings with `rule_id → RFC/NIST clause → severity → CVSS → CWE`, catalog per `03` §3 | M |
| FR-11 | Posture index 0–100 from 6 weighted sub-scores (20/25/15/15/10/15) + grade A–E | M |
| FR-12 | Confidence bounds (95% CI) + tri-state per evidence class; TLS-1.3 chain invisibility ⇒ x509 conf floor 0.15 | M |
| FR-13 | ML sweep (IsolationForest, AE, GCM-nonce reuse, entropy, JA3S drift, GBDT) that **only flags/ranks**; SHAP top features | M |
| FR-14 | Downgrade Radar: 5 signals → Bayesian `P(strip)` per MX, pinned priors | M |
| FR-15 | Delivery graph: enterprise → peers with mail counts, peer score, weakest-hop flag, exposure histogram | M |
| FR-16 | Enforcement consistency: DNS MTA-STS/DANE/TLS-RPT/DNSSEC × observed plaintext ratio → `CONSISTENT / VIOLATION / UNOBSERVED` | M |
| FR-17 | Decay / change-point: posture time-series per MX, JA3S baseline drift, changepoint flag | S |
| FR-18 | Evidence store persists every finding with provenance tuple + span hash; report hash = SHA-256 over serialized findings+evidence | M |
| FR-19 | `make verify` reproduces identical report hashes over `corpus/scenarios` | M |

### C. Posture Dashboard
| ID | Req | P |
|---|---|---|
| FR-20 | Per-MX score card: index, CI band, grade letter, tri-state counts, flow count | M |
| FR-21 | Heatmap of MX × service sub-scores (6 buckets) | M |
| FR-22 | Decay timeline chart (posture over windows) with changepoint markers | S |
| FR-23 | Enforcement panel: posted MTA-STS mode, DANE TLSA, TLS-RPT, DNSSEC, observed plaintext ratio, verdict | M |
| FR-24 | Drill from any MX card → its findings (pre-filtered) | M |

### D. Delivery Graph
| ID | Req | P |
|---|---|---|
| FR-25 | Force/lollipop graph: enterprise node + peer nodes, edge width = traffic, edge color = peer grade | M |
| FR-26 | Weakest-hop flags + "weakest hop" summary sentence ("leaks through these peers") | M |
| FR-27 | Click peer → its posture card | M |

### E. Findings Explorer + evidence
| ID | Req | P |
|---|---|---|
| FR-28 | Risk-ranked findings table: severity, rule_id, MX, service, CVSS, CWE, confidence; sortable | M |
| FR-29 | Filters: severity, rule_id, module, MX, service, state | M |
| FR-30 | Evidence drawer per finding: full provenance tuple + span hash + decoded bytes snippet | M |
| FR-31 | "Replay" button on each finding → Replay screen (or full-screen, if S-scope shipped) | M (button) / S (screen) |
| FR-32 | Export filtered findings as CSV | S |

### F. Reports & remediation
| ID | Req | P |
|---|---|---|
| FR-33 | JSON / PDF (WeasyPrint) / HTML export per session | M |
| FR-34 | Report shows: score+CI, all findings, radar, enforcement, graph summary, provenance, **report seal** | M |
| FR-35 | Remediation playbook per MX, LLM-generated (local Ollama), **every recommendation cites a rule_id** and is gated on deterministic findings | M |
| FR-36 | Hardening / "stay ahead" report section: policy rollout, key rotation, CT/OCSP, PQC readiness, monitoring thresholds | M |
| FR-37 | Playbook + hardening render fine with the LLM disabled (deterministic template fallback) | M |

### G. Stretch screens
| ID | Req | P |
|---|---|---|
| FR-38 | Incident Replay: animated timeline of a flow's protocol dialog + TLS handshake, critical moments flagged, scrubber, WebM export | S |
| FR-39 | Ask (RAG): grounded chat over findings; **must refuse** when retrieval score < threshold; every claim cites finding IDs; links back to evidence | S |
| FR-40 | Attack Lens: rank likely-next attacks from observed evidence per the `10` §4 mapping; each with likelihood + driving findings + "forecast not fact" label | S |
| FR-41 | Integrity: MANIFEST tree, per-file SHA-256, chain re-verification, tamper-flag branch | S |

### H. Cross-cutting
| ID | Req | P |
|---|---|---|
| FR-42 | Offline header badge + zero network calls except DNS (verifiable in logs) | M |
| FR-43 | Every module is a pure function of inputs + `package_ver`; no hidden clock/state | M |
| FR-44 | Single Docker image / `docker compose up` brings up backend + frontend; all images pre-pulled | M |
| FR-45 | Rule IDs are permanent & regression-stable; schema changes bump `package_ver` and re-hash | M |

---

## 5. Non-functional requirements (from `00` §5)

| ID | Req | Target |
|---|---|---|
| NFR-1 | 1 GB capture ingest | ≤ 1.5× tshark read time (single pass, batch DB flush) |
| NFR-2 | Score recompute | < 500 ms per 10k flows |
| NFR-3 | Full judge flow (upload → PDF) | < 90 s on a laptop |
| NFR-4 | Hardware | CPU-only laptop, 4 GB RAM, **no GPU** |
| NFR-5 | Network | fully functional offline; only optional DNS enrichment |
| NFR-6 | Reproducibility | `make verify` ⇒ byte-identical report hashes |
| NFR-7 | Stack | Python 3.12 + FastAPI backend; Next.js/React/TS frontend; SQLite; Docker |
| NFR-8 | Privacy | no plaintext SMTP bodies stored; metadata only |

---

## 6. Success criteria (demo acceptance)

The build is "done enough to present" when **all** of these are true on a rented laptop with **no internet**:

- [ ] Drop `corpus/scenarios/stripped.pcap` → Ingest auto-runs → within 3 clicks you see the `SMS-ENF-002` (stripped) finding with packet#, byte-offset, rule-ID in an evidence drawer.
- [ ] Posture renders as e.g. `58 [44–69] · D · low confidence` — with the CI band and a visible reason for low confidence (TLS 1.3 chain not observable).
- [ ] Delivery graph flags ≥1 weakest hop; enforcement panel shows a `VIOLATION` for the deliberately-misconfigured domain.
- [ ] PDF downloads, opens, and shows the SHA-256 report seal in the header.
- [ ] `make verify` exits 0.
- [ ] Wire pulled: all of the above still works; header reads `OFFLINE`.
- [ ] Remediation playbook renders (LLM on or off) and every line cites a `rule_id`.

Stretch screens (6–9) are bonus; they must never block criteria 1–7.

---

## 7. Build phases (detail + task IDs in `13`)

| Phase | Goal | Gate |
|---|---|---|
| **P0 Scaffold** | repo, pyproject, docker-compose, Makefile, CI, `.gitignore` | `make up` healthy |
| **P1 Core engine** | ingest→features→rules→score→evidence→reports (no UI polish) | CLI run on 1 scenario pcap prints a score |
| **P2 MVP UI** | screens 1–5 (Ingest, Posture, Graph, Findings, Reports) + live WS | demo path 3-clicks green |
| **P3 ML + radar + verify** | ML sweep, Radar, enforcement, decay, `make verify` | §6 criteria 1–5 |
| **P4 Hardening** | playbooks, hardening section, offline polish, demo assets | §6 criteria 6–7 |
| **P5 Stretch** | screens 6–9 (Replay, Ask, Lens, Integrity) | optional |

---

## 8. Risks & mitigations (mirrors deck Slide 9)

| Risk | Mitigation |
|---|---|
| Passive capture blind spots / TLS-1.3 | Tri-state `NOT-OBSERVABLE` + CI bands + published rubric |
| Labelling/model accuracy | testssl.sh oracle + model card (≥0.90 F1) + `make verify` |
| LLM hallucination | Rule-ID citation gate + deterministic fallback + refusal below retrieval threshold |
| Port 25 blocked by VPS provider | 587 smarthost + lab-local peer containers |
| No internet at venue | Air-gapped corpus in-app + recorded fallback |
| Scope creep across 9 screens | Core 5 (FR-1..37) gated before stretch (FR-38..41) |
| 2 GB upload memory blow-up | Streaming multipart, single-pass parse, batch flush |

---

*Cross-refs: `12-ui-spec.md` (screens) · `13-agent-build-plan.md` (tasks) · `00` architecture · `01` schema · `02` modules · `03` rubric/rules · `04` API · `05` lab · `09` usage · `10` advanced · `../SIH26159-SecureMailScope-Research.md` · deck `../SIH26159-SecureMailScope-Deck-Slides.md`.*
