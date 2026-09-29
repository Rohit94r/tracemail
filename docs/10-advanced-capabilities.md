# SecureMailScope — docs/10. Advanced Capabilities (the "wow" layer beyond the PS)
### Design-only. Five features that go past NTRO's literal deliverables and make the demo unforgettable:
### ① Incident Replay · ② RAG Chat with Findings · ③ Tamper-proof SHA-256 corpus · ④ Attack Lens (likely-next-attack) · ⑤ Hardening & Precautions ("stay ahead")

> Every feature is engineered to our rules: evidence-grounded, offline-first, honest confidence. No hype, no black-box.

---

## ① Incident Replay — "watch how it happened, like a video"

**What:** any finding/session can be replayed as an animated forensic timeline. The capture is rebuilt as a moving story: TCP stream → protocol dialog → STARTTLS negotiation → TLS handshake → cert exchange — with the **critical moments flagged and zoomed** (e.g., the exact frame where STARTTLS was advertised but body stayed plaintext).

**How:**
- The evidence store already keeps ordered events (flow_id, packet#, byte_offset, tls_record_idx, rule-ID). `Replay` renders them on a timeline with state-machine colors (SMTP/IMAP/POP3 grammar per `docs/01` §2).
- Flagged moments (from findings) pulse red with the rule-ID and a "why" chip.
- Exportable as **WebM/MP4** (local render, e.g., html2canvas/animation frames → ffmpeg) so judges get a video artifact for the deck.

**Interface:** "Replay" button on every finding + a full Incident Replay screen (play/pause/seek/speed, packet-by-packet scrubber).

**Guardrail:** replay shows *observed* packets only; anything NOT-OBSERVABLE is greyed with a label, never invented.

---

## ② RAG Chat with Findings — "ask your data plain questions"

**What:** an **Ask the data** panel where an analyst chats with their findings using a local LLM + retrieval: *"why is outlook's peer grade low?"*, *"what changed Tuesday?"*, *"explain this rule in simple words."*

**How:**
- Local embeddings (Ollama, e.g., `nomic-embed-text`) over: per-finding text, rule-ID catalog (`docs/03`), evidence snippets, report sections, and RFC/NIST clause text.
- Retrieval-augmented generation: every answer is **constrained to retrieved findings** and **must cite finding ID + evidence chain** (no free-floating claims). No data egress — fully offline.
- Answers link back to the Findings Explorer (one click → evidence drilldown).

**Guardrail:** hallucination control = the deterministic gates from `docs/02`; LLM is a summarizer over retrieved evidence, never a source of truth. Same rule as playbooks: every sentence cites a rule-ID.

---

## ③ Tamper-proof corpus & reports — SHA-256 integrity that survives scrutiny

**What:** capture files, extracted certs, findings, and reports form an auditable chain. Anyone can re-verify integrity after the fact — the exact property a forensic agency needs.

**How:**
- **Manifest:** every corpus deliverable registered in `MANIFEST.sha256` (file → SHA-256 + size + package_ver). A per-report **report seal** = SHA-256 over (manifest of source capture + findings + rubric version).
- **Chain:** chained hashing across chunks (block-chained) so reordering/removal is detectable; `make verify` recomputes and compares the full tree.
- **Repo hardening:** `.gitignore` for secrets, **signed git tags**, CI job runs `make verify` on every push; release zip ships `MANIFEST.sha256` + `report-hash.json`.
- **In-app:** the PDF/HTML report header shows the seal; Findings Explorer shows per-finding span hashes.

**Guardrail:** secrets never stored; manifest includes only hashes/metadata, never content.

---

## ④ Attack Lens — "what's most likely next, based on what we see"

**What:** not a crystal ball — **evidence-forward risk extrapolation**. Given observed posture + downgrade signals + drift + enforcement gaps, the app ranks the likely next moves of a path attacker *modeled on published attacker behavior* (IMC'15 path-attacker stripping stats, USENIX'21 injection patterns, NDSS'25 client-side silent downgrade observations), each with the evidence that drives it.

**How:**
- `evidence → candidate attack` mapping table (started below) scored by observed signal strength + NIST 800-131A/CNSA-2 urgency.
- Each prediction shows: attack class, likelihood (low/med/high + a confidence label), the exact findings driving it, and the precondition the attacker would use.
- Outputs feed the mitigation plan (feature ⑤).

| Observed evidence | Most-likely next attack (modeled) | Driver citation |
|---|---|---|
| advertised-but-unused STARTTLS at high volume | Full stripping → cleartext capture of mail metadata/content | IMC'15 (Tunisia 96%) |
| cert-hostname mismatch / no validation | Successful MITM — attacker presents own cert | CCS'15 (>50% MTAs no validation) |
| weak cipher / TLS≤1.1 negotiable | Downgrade-then-decrypt or SWEET32 session hijack | RFC 9325 / CVE-2016-2183 |
| nonce reuse detected | Record forgery / authenticated-FE decryption of a few records | WOOT'16 (Böck) |
| policy says enforce, traffic shows plaintext | Enforcement-bypass persist (MTA-STS/DANE evasion) | IMC'25 MTA-STS misconfig 29.6% |
| JA3S drift / posture decay over windows | Active reconfiguration or ongoing intrusion | Pillar-4 change-point model |

**Guardrail:** labeled **forecast not fact**; every forecast requires ≥1 observed finding; confidence shrinks when evidence is thin.

---

## ⑤ Hardening & Precautions — "stay ahead, not just fix"

**What:** beyond "fix now" remediation playbooks, an **stay-ahead layer**: preventive posture and a hardening calendar.

**How — two report sections + a checklist per deployment lane:**
- **Fix now** (remediation, existing): enforce TLS1.2+/1.3, AEAD+ECDHE, MTA-STS `enforce`+TLS-RPT, DANE rollover, Postfix/Dovecot configs.
- **Stay ahead** (precautions):
  - Policy rollout plan (MTA-STS testing→enforce, DANE with rollover strategy, TLS-RPT monitoring).
  - Forward-security hygiene: key rotation schedule, CT/OCSP-to-stapling practice, **PQC readiness / harvest-now-decrypt-later awareness** (CNSA 2.0, NIST 800-131A).
  - Monitoring thresholds: what to watch next (downgrade indicator counts, cert-rotation events, JA3S drift), with trigger levels.
  - Incident-readiness checklist per lane (SOC probe / DFIR / fleet survey), referencing `docs/09` §5.

**Guardrail:** every stay-ahead item maps to a rule-ID or a standards reference; nothing invented.

---

## Integration & roadmap fit

| Feature | Plugs into | MVP? | Phase |
|---|---|---|---|
| ① Incident Replay | Reports/Dashboard (new screen + "Replay" button) | no (stretch) | P4+ |
| ② RAG Chat | Dashboard chat panel; Reports engine reuse | no | P4+ |
| ③ SHA-256 tamper-proof | Evidence store + corpus + CI (`make verify`) | yes (base part already) | P1 (store) / P5 (manifest+CI) |
| ④ Attack Lens | ML layer + rule engine (fast picture) | no (stretch) | P5 stretch |
| ⑤ Hardening & Precautions | Reports engine (second section) | partial (static playbook) | P4 |

**Demo budget (~90s total):** one replay of the stripped session (30s) → chat "why is this MX weak?" (20s) → hash seal on the PDF + `make verify` green (20s) → Attack Lens "most likely next" for the same capture (20s).

---

*Cross-refs: evidence store ↔ `docs/01`; report engine ↔ `docs/02` M10; APIs ↔ `docs/04`; corpus ↔ `docs/05`; deck ↔ `../SIH26159-SecureMailScope-Deck-Slides.md`.*