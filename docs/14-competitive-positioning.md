# SIH26159 SecureMailScope — 14. Competitive Positioning (corrected after competitor video analysis)

> **Basis:** analysis of 3 competing SIH26159 team demo videos (transcripts reviewed; feature matrix extracted). This doc governs *how we talk about* our features — it does **not** remove any capability.
>
> **Core principle: capability ≠ claim.** We build and keep **everything** — the PS mandates it, and a rival having it changes nothing about whether we need it. What changes is only the label we attach: **table-stakes = required, present, not novel** vs. **differentiator = the thing nobody else does**.

---

## 1. The corrected mental model

| | Meaning | Effect on build | Effect on pitch |
|---|---|---|---|
| **Capability** | A thing the software does | **Never cut** because a rival has it | — |
| **Table-stakes claim** | PS requirement, all rivals have it | Build fully | State it, don't claim novelty |
| **Differentiator claim** | Unclaimed by all 3 rivals | Build fully | **Lead with it** |

**The failure mode to avoid:** dropping a capability because Team 2 has it. That would be a straight self-inflicted wound — the PS asks for it, and judges tick boxes against the PS, not against rivals.

**The failure mode to avoid (mirror):** claiming novelty for something a rival demonstrably has. A judge who watched all three videos will catch it, and an overclaim costs more credibility than a modest differentiator ever earns.

---

## 2. PS requirements — unchanged, all still built

NTRO's 5 deliverables. **All mandatory. All rivals have some form of these.** We implement all of them, at depth, and label them as *compliance*, not novelty.

| # | NTRO requirement | Our capability | Build | Pitch as |
|---|---|---|---|---|
| 1 | Protocol ID + TCP stream reconstruction + STARTTLS upgrade detection | Ingest/parse, 6-class state machine | **MUST** | Compliance |
| 2 | TLS handshake reconstruction; X.509 extraction + validation | Rule engine X509 bucket (RFC 5280 §6, CWE-295–298) | **MUST** | Compliance |
| 3 | Flag deprecated TLS / weak ciphers / weak KEX / missing FS | Rule engine PROTO/CIPH/KEY (RFC 9325, NIST 800-52r2) | **MUST** | Compliance |
| 4 | AI/ML: risk classification, anomaly detection, posture scoring, threat prioritization, deviation alerts | ML layer + 0–100 index + CI + `/ws/live` alerts | **MUST** | Compliance |
| 5 | Outputs: JSON + PDF + HTML forensic reports + interactive dashboard | Reports engine + 5 core screens | **MUST** | Compliance |

**Dataset:** synthetic allowed by the PS → 5 scenario PCAPs + real production-mailbox corpus.

---

## 3. Capability inventory — keep status by rival coverage

Legend: **T1/T2/T3** = the three rival demos. `—` = absent from their video. Build status is **unchanged in every row**.

### 3.1 Present across rivals → table stakes (build fully, do NOT claim novelty)

| Capability | T1 | T2 | T3 | Our status | Pitch as |
|---|:--:|:--:|:--:|---|---|
| TLS / certificate analysis | 🟢 | 🟢 | 🟢 | Build (PS #2, #3) | Compliance |
| PDF / HTML / JSON reporting | 🟢 | 🟢 | 🟢 | Build (PS #5) | Compliance |
| Remediation guidance | 🟢 | 🟢 | 🟢 | Build | Compliance |
| Passive PCAP analysis | — | 🟢 | 🟢 | Build (PS #1) | Compliance — **no longer a differentiator** |
| Packet-level evidence linkage | — | 🟢 | — | Build | Compliance — **retract "zero of 15 rivals"** |
| "Not observable" distinction | — | 🟢 | — | Build (tri-state) | Compliance — **demote from moat** |
| Cryptographic drift / JA3S decay | — | 🟢 | — | Build | Compliance — **retract as novelty** |
| Isolation Forest | 🟢 | — | — | Build (ML) | Implementation detail |
| SHAP / explainable AI | — | — | 🟢 | Build (ML) | Implementation detail |
| JA3 / JA4 fingerprints | — | — | 🟢 | Build (features) | Implementation detail |
| NIST / PCI DSS mapping | — | — | 🟢 | Build (rubric) | Implementation detail |
| Live socket monitoring | — | — | 🟢 | Build (`/ws/live`) | Compliance — **demote** |
| Controlled client scenarios | — | — | 🟢 | Build (weak-lab) | Compliance — **demote** |
| Domain-centric analysis | 🟢 | — | — | Build (per-MX) | Compliance |

### 3.2 Absent from all three → **differentiators (lead with these)**

| # | Differentiator | Why it's unclaimed | Where it lives |
|---|---|---|---|
| **D1** | **Downgrade Radar** — Bayesian `P(strip)` per MX from 5 signals | Rivals do *post-hoc* crypto scoring; nobody *predicts stripping likelihood* | `docs/03` §4 · radar module |
| **D2** | **Cross-hop delivery graph** — weakest-hop + traffic-weighted exposure | Rivals score the server you gave them; nobody maps *where mail leaks* across hops | graph module |
| **D3** | **Enforcement-consistency** — posted MTA-STS/DANE/TLS-RPT vs. *observed* traffic → `VIOLATION` | Rival "NIST mapping" is a compliance *label*; this is a *violation detector* | enforce module |
| **D4** | **Confidence bounds + published reproducible rubric** | Rivals flag "not observable"; nobody publishes a **CI-banded, hash-reproducible** score | `docs/03` §2 |
| **D5** | **Tamper-evident reproducibility** — `make verify` → identical SHA-256 | No rival demonstrates byte-identical score re-derivation | evidence store |
| **D6** | **Beyond-PS layer** — Incident Replay · RAG chat · Attack Lens · Integrity · PQC/CNSA-2 | Entirely outside the PS; competitors stopped at reporting | `docs/10` |

---

## 4. Positioning line (replaces the dead "camera vs door-knocker")

The old line — *"everyone knocks on the door, NTRO asked for a camera"* — is **retired**. Passivity is now table stakes; leading with it invites a direct "Team 2 did that too."

**New line:**

> *"Three other teams also read PCAPs. None of them can tell you whether your mail is being stripped, or which hop it leaks through — and none of them can reproduce their own score a week later."*

**Secondary line (compliance framing):**

> *"We do the full PS — protocol reconstruction, X.509 validation, weak-crypto flagging, ML prioritization, JSON/PDF/HTML — and then we do the part nobody does: predict the downgrade, trace the weak hop, prove the enforcement gap, and seal the score so it can be reproduced."*

---

## 5. Required edits to existing material

| File | Fix |
|---|---|
| `../SIH26159-SecureMailScope-Deck-Slides.md` L46 | Retract "zero of 15 rival repos" (Team 2 has packet-level linkage) |
| `../SIH26159-SecureMailScope-Deck-Slides.md` L52 | Replace "strong rivals miss all six" with the corrected **D1–D6** list |
| `../SIH26159-SecureMailScope-Deck-Slides.md` L108 | Risk row: replace "10-differentiator bundle" with "competitor teardown done; D1–D6 unclaimed" |
| `../SIH26159-SecureMailScope-Research.md` §7.4 | Renumber the differentiator list → D1–D6; move IF/SHAP/JA3 to implementation details |
| `../SIH26159-SecureMailScope-Research.md` §7.2 | Update verdicts: PASSIVE, EVIDENCE-CHAIN, TRI-STATE, DRIFT move PARTIAL→CLAIMED |
| `docs/10-advanced-capabilities.md` | Retitle framing: D6 is the unclaimed layer; keep all five features |

**No code, schema, module, or API change results from this doc.** It is a messaging correction only.

---

## 6. Honest caveats

- Analysis is based on **demo videos** — absence from a video is weaker evidence than absence from a repo. Phrase as *"not demonstrated by the three teams we reviewed"*, not *"nobody has built this"*.
- The transcripts were not in the workspace; this doc reflects the extracted feature matrix. Re-verify specific cells if a transcript contradicts one.
- D4/D5 are **depth** advantages, not categorical ones — claim them as rigor, not as novelty.

---

*Cross-refs: PRD `11-prd.md` · UI `12-ui-spec.md` · build plan `13-agent-build-plan.md` · rubric `03` · advanced `10` · research `../SIH26159-SecureMailScope-Research.md` · deck `../SIH26159-SecureMailScope-Deck-Slides.md`.*
