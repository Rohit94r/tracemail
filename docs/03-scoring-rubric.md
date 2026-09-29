# SIH26159 SecureMailScope — 03. Scoring Rubric & Rule ID Catalog

Design-only. Ground truth = RFC 9325 / NIST SP 800-52r2 / RFC 5280 / RFC 6698·7672·8461·8460. Rule IDs are permanent once shipped (regression-stable).

## 1. Posture Index = weighted sub-scores

| Sub-score | Weight | Basis |
|---|---|---|
| `sub_protocol` — TLS≥1.2, no ≤1.1, no downgrade | 20% | RFC 9325 §3.1/§3.1.3, NIST 800-52r2 |
| `sub_cipher` — AEAD, PFS, ≥112-bit, no static RSA/null/anonymous | 25% | RFC 9325 §4.1–4.2 |
| `sub_key` — RSA/DH ≥2048, ECDH ≥224, P-256/X25519, no SHA-1 | 15% | RFC 9325 §4.5 |
| `sub_x509` — chain/validity/issuer/mismatch/expiry (CWE-295..298) | 15% | RFC 5280 §6, RFC 6960 |
| `sub_dns` — MTA-STS, DANE TLSA, TLS-RPT, DNSSEC, SPF/DKIM+DMARC(p) | 10% | RFC 8461/6698/8460 |
| `sub_enforce` — downgrade-indicator & enforcement-trace counts | 15% | IMC'15, USENIX'21 EAST |

```
posture_index = Σ(weightᵢ × subᵢ)        // each subᵢ in [0,1] × 100
```

Each `subᵢ` is a **fraction deducting only for ruled findings**: start at 1.0, subtract per active finding's severity deduction, floor at 0. A finding is active only if it maps to an observation (or known DNS record); unobservable → excluded from score, recorded `NOT-OBSERVABLE` (never a deduction).

## 2. Confidence bounds (the UNCLAIMED differentiator)

- Foundational: each sub-score carries `sub_confᵢ` ∈ [0,1]:
  - `x509` confidence: 1.0 when ciphertext is ≤TLS1.2 and session upgraded (chain visible); **0.15 floor under TLS1.3** or downgraded-session (chain invisible) → report "chain NOT-OBSERVABLE".
  - cipher/protocol conf: 0.9 unless ClientHello-vs-server asymmetry observed (see blackboard), then 0.5.
  - enforce/dns conf: 0.8 (DNS reads are live states); 1.0 for observed-session counters.
- Aggregate:
  ```
  μ = Σ wᵢ·subᵢ ;  σ² = Σ wᵢ²·(1−sub_confᵢ)·(1−0)·VarBound  // simplify: σᵢ = 7.5×(1−sub_confᵢ)
  ci_low  = clamp(μ − 1.96·σ, 0, 100)
  ci_high = clamp(μ + 1.96·σ, 0, 100)
  ```
- Report string e.g. `Posture 82 [71–91] · chain not-observable (TLS1.3) · 3 flags medium+`.
- The rubric JSON lists which rules fired under each bucket and the deductions taken. Judges can reproduce any number.

## 3. Rule ID namespace

`SMS-<CAT>-<NNN>` where `<CAT>` in `PROTO · CIPH · KEY · X509 · DNS · ENF · RADAR · ML`.

| rule | finding trigger | severity | CWE | sample CVSS4 |
|---|---|---|---|---|
| `SMS-PROTO-001` | negotiated TLS ≤1.1 (RFC 9325 §3.1.1) | high | CWE-326 | CVE-2024-23656 8.7 |
| `SMS-PROTO-002` | fallback observed (downgraded version) §3.1.3 | high | CWE-757 | CVE-2024-23656 8.7 |
| `SMS-CIPH-001` | NULL/anonymous/RC4/export/CBC-without-ETM §4.1–4.2 | high | CWE-327 | SWEET32 CVE-2016-2183 7.5 |
| `SMS-CIPH-002` | non-PFS suite negotiated §4.1 (DHE SHOULD-NOT) | medium | CWE-326 | CVE-2016-6321 5.9 |
| `SMS-CIPH-003` | AES-GCM nonce reuse across records §7.2.1 | critical | CWE-324 | CVE-2016-1284 4.3/7.5 |
| `SMS-KEY-001` | RSA/DH <2048 §4.5 | high | CWE-326 | — |
| `SMS-KEY-002` | SHA-1/MD5 signature §4.5 | medium | CWE-327 | — |
| `SMS-X509-001` | chain-unvalidated (RFC 5280 §6), CN/SAN mismatch | high | CWE-295 | — |
| `SMS-X509-002` | expired / self-issued in path | high | CWE-298 | — |
| `SMS-X509-003` | unsigned-cert-SCT absence (log) | info | — | — |
| `SMS-DNS-001` | MTA-STS none or `testing` (no enforce) on inbound-capable domain | medium | CWE-319 | — |
| `SMS-DNS-002` | DANE TLSA invalid/unusable §3.7 (RFC 7672) | medium | CWE-326 | — |
| `SMS-DNS-003` | DNS anomaly resolved (policy enforce ≠ observed) → handled in ENF | — | — | — |
| `SMS-ENF-001` | advertised but unused STARTTLS (per session) | medium | CWE-319 | — |
| `SMS-ENF-002` | stripped: STARTTLS → plaintext continues | high | CWE-757 | — |
| `SMS-ENF-003` | 454/"Must issue" per session with >N repeats | medium | CWE-319 | — |
| `SMS-ENF-004` | violation: MTA-STS `enforce` but observed plaintext ratio > 1% | high | CWE-319 | — |
| `SMS-ENF-005` | implicit-TLS port (465/993/995) served in cleartext, incl. cleartext credentials (RFC 8314 §3) | high | CWE-319 | — |
| `SMS-RADAR-001` | P(strip) > 0.5 on any MX | high | CWE-757 | — |
| `SMS-RADAR-002` | observed cert ≠ CT-published hash (span includes pin-match) | critical | CWE-295 | — |
| `SMS-RADAR-003` | JA3S multiplicity >1 for same MX | low | CWE-757 | — |
| `SMS-MLNA-001` | nonce reuse (also CIPH-003, cross-signal elevated, e.g. duplicate IV) | critical | CWE-324 | — |
| `SMS-MLNA-002` | randomness entropy anomaly (histogram-entropy + repeat-bucket) | info | CWE-330 | — |
| `SMS-MLNA-003` | JA3S drift / change-point posture decay | medium | CWE-757 | — |

`state ∈ SECURE|VULNERABLE|NOT-OBSERVABLE` per finding. Grade letter mapping (for the deck): **A** = 90–100 · **B** = 70–89 · **C** = 50–69 · **D** = 30–49 · **E** = 0–29, shown alongside CI band.

## 4. Radar priors (pinned, cited)

```
P(strip) prior            = 0.20        # IMC'15 ~20% active-corruption sample (shadowmail ≈ 20%)
P(no-tls-follow | strip)  = 0.90        # Suricata/EAST machine counters
P(unused | honest)        = 0.25
CT-cert-drift composite   = shift via crt.sh hashes; prior 0.05  # HotNets'25
```
These constants live in `backend/config.py` with the citation comment, and are overridable only via rubric_json (re-bump package_ver).

## 5. Oracle cross-check (accuracy proof for Q&A)

- At capture time: `testssl.sh -t smtp|imap|pop3 <mx:port>` grades A–F (its A–E grade, capped at "T" for STARTTLS). Save oracle output in corpus metadata.
- Regression: for each scenario in `corpus/scenarios`, expected report-hash + expected `posture_index` range stored in `corpus/expected/`. `make verify` fails if any drift.