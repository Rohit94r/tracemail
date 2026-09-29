# SecureMailScope — docs/09. Usage Model (how users actually deploy & use it)
### Design-only. Answers: "where does this run, how does data get in, what does a user do each day?"

---

## 1. The principle (read first — this kills the confusion)

**SecureMailScope is NOT a hosted website and users do NOT "connect their mail" to us.**

It is **self-hosted software** you run inside your own environment — like an antivirus or a security camera, not like Gmail. The camera is installed on *your* property, watches the envelopes pass, never touches them, and reports to *you*.

- Users never give us mail credentials. We never log in to a mail server.
- We never read email content. We only observe **network-boundary traffic** (the SMTP/IMAP/POP3 handshakes) produced by the user's own mail infrastructure.
- "Our VPS + our domain mailbox" exists **only as our demo proof** ("here is real traffic being scored") — it is not a product feature where customers connect their mail.

---

## 2. Deployment targets

| Target | What runs | Mode | Typical owner |
|---|---|---|---|
| **Analyst laptop** (primary, air-gapped) | app via Docker/`docker compose` | Capture upload / folder watch | DFIR analyst, SOC analyst, admin |
| **Network server** (their infra) | backend + agent container | Continuous folder watch / live feed | Enterprise SOC |
| **Reference demo VPS (ours)** | full stack + capture agent + real mailbox on our domain | Live feed (demo only) | Our team |
| **Fleet controller** (gov/CERT/ISP) | offline batch runner over many captures | Batch upload / offline corpus | CERT-In, ISP, regulator |

All targets are **offline-capable**; internet is an optional enrichment (DNS record reads) only.

---

## 3. Three ways data gets in

### Mode A — Upload a capture (the main judge-facing and DFIR workflow)
1. Analyst already has a `.pcap`/`.pcapng` (from `tcpdump`, Wireshark, a mirror/SPAN port, cloud mirror, or a responder's handoff).
2. Drag-drop into the app (or `POST /api/v1/captures/upload`).
3. App returns session + flow counts + warnings, then score, findings, evidence drilldown, report.

### Mode B — Point at a capture folder (continuous SOC monitoring)
1. User runs our thin capture agent (or any tcpdump loop) that writes 60s chunks into `lab/live/`.
2. App watches the folder (`/api/v1/captures/from-folder`) and scores each new chunk automatically.
3. Posture history accumulates → decay/time-series view meaningful over days.

### Mode C — Live feed (advanced / our demo)
1. Agent on a network boundary forwards chunks → `/ws/live` live dashboard updates.
2. A mail sent now appears in seconds; alerts fire on deviation.

---

## 4. The end-to-end SOC workflow (what a real user does)

1. **Detect** — network trigger or scheduled scan produces a capture.
2. **Analyze** — drop capture in SecureMailScope; get posture score with confidence band.
3. **Prioritize** — risk-ranked findings list (severity + CVSS + CWE).
4. **Interrogate** — click a finding → evidence chain (packet#, byte offset, rule-ID); hit **Replay** to watch the session unfold (docs/10: Incident Replay); **Ask the data** (RAG chat) for a grounded plain-language explanation.
5. **Record** — export JSON/PDF/HTML (hash-signed); file with audit.
6. **Fix & stay ahead** — remediation playbooks ("fix now") + hardening precautions ("stay ahead", docs/10) applied by the admin.
7. **Prove** — `make verify` reproduces identical report hashes (tamper-evident corpus, docs/10).

---

## 5. What we show judges at SIH (maps to the usage model)

| Demo beat | Mode shown | Audience takeaway |
|---|---|---|
| Drop `stripped.pcap` → flag + evidence drilldown | A | ready-to-use forensic workflow |
| Live: test mail sent → scored in seconds on our real mailbox | C | production-grade, not mock |
| Delivery graph from days of real corpus | B | continuous monitoring vision |
| Replay + chat + hash seal (30s each) | A | the "wow" layer |

---

## 6. FAQ (pre-armed answer lines)

| "Do users connect their mail?" | "No credentials, no login to any mail server — traffic observation only, on your own boundary." |
|---|---|
| "Do you read my emails?" | "Never. Handshakes, certificates, version/cipher negotiation — metadata only." |
| "Does it need the internet?" | "No. Offline-first; internet is optional DNS enrichment only." |
| "Where does my data go?" | "Nowhere. It never leaves your machine; reports are generated locally." |
| "What about the demo mailbox on your domain?" | "That's our proof-of-reality — your data is never involved." |

---

*Cross-refs: deployment lanes ↔ Research §8 / Roadmap §4; agent spec ↔ docs/05; APIs ↔ docs/04.*