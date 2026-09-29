# SIH26159 SecureMailScope — 15. Landscape Gaps vs. Our Build Scope (verified audit)

> **Purpose:** answer one question — *for every existing solution and every key gap, do we already build it, and if not, is that deliberate?* Audited against the build contracts (`11-prd.md`, `13-agent-build-plan.md`, `03-scoring-rubric.md`, `10-advanced-capabilities.md`).
> **Rule:** a gap we deliberately do **not** fill is fine **only** if it conflicts with the PS (passive, no scanning). Every other gap is either in scope or scheduled.

---

## 1. Verdict legend

| Symbol | Meaning |
|---|---|
| ✅ **IN** | In our build scope, scheduled with a task ID |
| 🟡 **PART** | Partially in scope — the base is built, the advanced part is scheduled later |
| ⛔ **BY DESIGN** | Deliberately **not** built — conflicts with the PS (active probing / scanning) |
| ❌ **MISSING** | A real gap we do **not** currently cover → needs a decision |

---

## 2. Commercial & adjacent products

| Solution | What it does | Key gap | Our status |
|---|---|---|---|
| **testssl.sh** | Active-probes a host, grades TLS A–F. **Caps STARTTLS at "T"**; no enforcement check (issue #1832) | Can't see a passive capture; no downgrade likelihood; STARTTLS posture capped | ✅ IN — used as our **oracle** (`03` §5), not as a product. We add the 6-class STARTTLS state machine + enforcement-consistency it lacks |
| **SSLyze** | Fast active TLS scanner, scan modes | Active → PS-violating for us; no score/CI/graph | ⛔ BY DESIGN (active) — we take its parsing ideas only |
| **Hardenize / SecurityScorecard / BitSight / UpGuard** | DNS/website security grades | DNS-only or web; no mail-packet evidence | ⛔ BY DESIGN (DNS/web, not capture) |
| **PQProbe** | **Closest product**: grades SMTP/IMAP/POP3 TLS from a passive capture (A–F + trajectory) | PQC-focused; per-device not per-domain; **no delivery graph / cross-hop**; no confidence bounds; no enforcement check | ✅ IN — we are the multi-domain, CI-banded, graph+radar version. Preempt it by name in Q&A |
| **Google Postmaster Tools** | Passive-derived TLS% time series; "Recipient Domains Not Supporting TLS" | No score, no graph, no evidence chain, no radar | ✅ IN — we add scoring + graph + radar on top of the same passive idea |
| **MS365 Transit-Security report** | Passive TLS% + weak-domain list | List only; no scoring, no graph, no radar | ✅ IN — same as above |
| **CaptainDNS TLS-RPT analyzer** | 0–100 health from sender TLS-RPT reports | Only *your own inbound*; only domains that publish reports | ✅ IN — we infer from observed traffic, not sender reports |
| **internet.nl / NCSC-UK Mail Check** | Domain/mail policy checks (SPF/DKIM/DMARC/MTA-STS) | DNS-policy only; **no observed-traffic correlation** | ✅ IN — we add the *observed vs posted* cross-check (D3) |

---

## 3. Research & tooling prior art

| Source | Contribution | Key gap | Our status |
|---|---|---|---|
| **Durumeric IMC'15** | 41,405 strippers; Tunisia 96% | Measurement study, not a tool | ✅ IN — feeds **D1** radar priors (`03` §4) |
| **Poddebniak USENIX'21 (EAST)** | 40+ STARTTLS flaws; 320k injectables | Active test suite; no posture score | ✅ IN — we reinterpret its state classes passively (state machine) |
| **Foster CCS'15** | >50% MTAs never validate certs | Study only | ✅ IN — cert-validation findings (PS #2) |
| **Böck WOOT'16** | GCM nonce reuse (184 servers) | Study only | ✅ IN — `SMS-CIPH-003` / `SMS-MLNA-001` |
| **Heninger USENIX'12** | Weak keys / RNG | Study only | ✅ IN — key-strength + entropy rules |
| **Blechschmidt USENIX'23** | 30% invalid certs | Ecosystem stats | ✅ IN — calibrates "normal vs alert" |
| **Lee USENIX'20/'22**, **Ashiq IMC'25** | MTA-STS/DANE adoption + misconfig | Study only | ✅ IN — D3 enforcement-consistency |
| **HotNets'25 CT-downgrade oracle** | CT-vs-observed cert drift | **Proposal only, not built** | 🟡 PART — `CERT_CT_DRIFT` is a radar signal; a full CT oracle is **not** in MVP |
| **certspotter** | Cert-transparency watchlist | Watchlist, not capture-driven | ⛔ BY DESIGN (external watch service) |

---

## 4. SIH 2026 rival repos (same PS, weeks before us)

Three demo videos reviewed + 15 public repos scanned. **Every "claimed" row is still built by us** — the PS requires it — we just don't claim novelty.

| Rival | Their angle | Their gap we can beat | Our status |
|---|---|---|---|
| **Team 1** | Domain-centric + IsolationForest + reporting | No passive-evidence chain, no radar, no graph, no CI | ✅ IN — superset |
| **Team 2** | Passive PCAP + packet evidence + "not observable" + drift | **No** downgrade prediction, **no** delivery graph, **no** enforcement check, **no** reproducibility, **no** Replay/chat/Lens | ✅ IN — D1–D6 are exactly their blind spots |
| **Team 3** | JA3/JA4 + SHAP + NIST map + live + controlled scenarios | NIST mapping is a *label*, not a *violation detector*; no radar, no graph, no CI, no reproducibility, no Replay/chat/Lens | ✅ IN — D1–D6 are exactly their blind spots |
| **`pitu2k/Securemailscope`** | Rule+ML, iForest, PQC kex, TLS1.3 honesty | PQC is a single signal; no graph, no radar, no enforcement, no replay | ✅ IN — we go deeper (D5, D6) |
| **`soumyajit-cys/CipherPost`** | GBM 0–100 + iForest + SHAP | Score is uncalibrated (no CI); no evidence chain, no radar, no graph | ✅ IN — D4 (CI + published rubric) fixes their weakness |
| **`shashwat4130/MailRakhwala`** | tshark + cert audit + STARTTLS + SHAP | Naive STARTTLS string-match; no radar, no graph, no CI | ✅ IN — 6-class state machine supersedes string-match |
| **`dhanush-girish/securemailscope`** | tshark→CSV→RF/iForest→live dashboard | **Drifts into active scanning** (PS violation); no CI, no graph, no radar | ✅ IN — we stay PS-literal; their live-scan approach is a liability we avoid |
| **`xarjunpatil/SIH26159-…`** | Landslide-GIS template left in whitepaper | Sloppy; nothing to borrow | ⛔ n/a |
| **~10 shallow clones** | Near-empty templates | — | ⛔ n/a |

---

## 5. Gap-by-gap verdict (the direct answer)

| # | Gap in the field | In our scope? | Task |
|---|---|---|---|
| 1 | Predict **stripping** (P(strip)) from passive signals | ✅ IN | P3-2 |
| 2 | **Cross-hop weakest-hop** exposure map | ✅ IN | P3-4 |
| 3 | Detect **policy-vs-reality** violation (MTA-STS/DANE vs observed) | ✅ IN | P3-3 |
| 4 | **CI-banded** score + **published** rubric | ✅ IN | P1-4 (score), D4 |
| 5 | **Reproducible** score (identical SHA-256 on re-run) | ✅ IN | P3-6 (`make verify`) |
| 6 | **Incident Replay** (animated forensic timeline) | ✅ IN — **promoted to MVP** | P3-7 |
| 7 | **Grounded RAG chat** over findings | 🟡 PART — stretch (needs local LLM) | P5-2 |
| 8 | **Attack Lens** (forecast next attack) | ✅ IN — **promoted to MVP** | P3-8 |
| 9 | **Tamper-proof manifest** + chain verify UI | 🟡 PART — base in P1-5, manifest/UI in P5-4 | P1-5 / P5-4 |
| 10 | **Stay-ahead hardening** (PQC, rotation, calendar) | 🟡 PART — static playbook in P4, full in P5 | P4-2 |
| 11 | **CT-vs-observed** cert drift (full CT oracle) | 🟡 PART — signal only | P3-2 (signal) |
| 12 | Active probing of live hosts | ⛔ **BY DESIGN** | PS-forbidden |
| 13 | External CT watchlist service | ⛔ **BY DESIGN** | out of scope |

**Bottom line:** every meaningful gap is **already in our build scope** — nothing is ❌ MISSING. The six D-gaps (1–5) are **core MVP**; the beyond-PS layer (6–10) is **scheduled in P4–P5**. The only things we decline are the two that would violate the passive PS (12–13).

---

## 6. ⚠️ Two inconsistencies found in our own docs (fixed)

1. **Re-prioritization needed.** `docs/10` still marks Replay / RAG / Attack Lens as "no (stretch), P5". Given D6 is now a *primary* differentiator, **Replay + Attack Lens should move into MVP**; RAG chat stays stretch (needs a local LLM). → See `docs/10` updated table + build-plan note.
2. **CT oracle wording.** `docs/03` lists a `CERT_CT_DRIFT` radar signal; this doc records that a *full* CT oracle is signal-only (not MVP). Consistent — no code change, just honest labelling.

---

*Cross-refs: PRD `11-prd.md` · build plan `13-agent-build-plan.md` · rubric `03` · advanced `10` · positioning `14` · research `../SIH26159-SecureMailScope-Research.md`.*
