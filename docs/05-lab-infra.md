# SIH26159 SecureMailScope — 05. Lab & Infra (real production mailbox)

Design-only. This is what turns the demo from "lab data" to "live production-grade" using our own domain + VPS + real mailbox. All infra work in `lab/`.

## 1. Topology

```
VPS (public IP, ports 25/465/587/993/995 open)
 ├─ strong  Postfix + Dovecot  ▸ real domain mailbox   (mail.<domain>, TLS1.2/1.3-only, hardened)
 ├─ weak    Postfix + Dovecot  ▸ weak-lab.<domain>     (TLS1.0, export ciphers, RSA-1024/SHA-1, expired/self-signed)
 └─ agent   tcpdump → 60s chunks → lab/live/ → engine  (passive, metadata only)

Local dev laptop ▸ docker compose: backend + frontend + ollama; points at lab/live/ or uploaded PCAP
```

**Traffic generator** (cron): hourly real sends to Gmail / Outlook / Proton / iCloud / corporate test-mailboxes; inbound auto-replies (e.g., a second Google account replying) → steady live flows; scheduled weak-lab probes.

## 2. DNS checklist (real domain)

| Record | Purpose | Check with |
|---|---|---|
| MX → mail.<domain> priority 10 | routing | `dig MX` |
| SPF `include` + `-all` | anti-spoof | `dig TXT` |
| DKIM `default._domainkey` selectors | signing | `dig TXT default._domainkey` |
| DMARC `p=quarantine` + `rua` | reporting | `dig TXT _dmarc` |
| MTA-STS `_mta-sts.<domain>` → `v=STSv1;id=1;enforce;mx=mail.<domain>` | enforce | `dig TXT _mta-sts` |
| MTA-STS policy `https://mta-sts.<domain>/.well-known/mta-sts.txt` | presence | curl |
| TLS-RPT `_smtp._tls.<domain>` → `v=TLSRPTv1;rua=mailto:…` | feedback | `dig TXT _smtp._tls` |
| DANE TLSA (optional but powerful) | pin | `dig TLSA _25._tcp.<domain>` |
| DNSSEC (DS at registrar) | integrity | `dig +dnssec` |

**Weak-lab** deliberately leaves MTA-STS/DANE off and publishes mismatching/expired certs — gives Enforcement-consistency + radar real negative findings without damaging the real domain's reputation.

## 3. Capture agent

- `tcpdump -i <iface> -s 262144 -w lab/live/<ts>.pcap -G 60 -W 0 'port 25 or port 465 or port 587 or port 993 or port 995'`
- Rotation: read after 60s; chunk pushed to `/api/v1/captures/from-folder` (path allow-listed) OR parked for batch import.
- Metadata-only guarantee: agent never logs decrypted content; only the 5-tuple + TLS handshake fields (set `-n` to avoid host lookups, and never `-A`).
- Optionally mirror to Zeek log files for enrichment (`ssl.log`, `x509.log`, `ocsp.log`) — optional path per interface doc.

## 4. Corpus layout & regression harness

```
corpus/
 ├─ scenarios/
 │    weak-smtp.pcap           TLS1.0/RC4/RSA-1024/SHA-1/expired cert      → testssl grade “F”
 │    strong-smtp.pcap         TLS1.3/ECDHE-GCM/P-256/RSA-2048 SAN chain   → “A”
 │    stripped.pcap            EHLO advertises STARTTLS → plaintext body   → radar high
 │    tls13-notobservable.pcap X.509 invisible → tri-state honesty proof   → NOT-OBSERVABLE
 │    pq-hybrid.pcap           ML-KEM/hybrid key-exchange → HNDL flag      → radar/ML cross-signal
 ├─ live/                      VPS agent chunks (real mailbox, collected over days)
 └─ expected/
      *.hash.json              {report_hash, posture_index_range, rule_ids_fired}
```

`make verify`: re-run pipeline over scenarios + a live directory sample; assert report-hash equality + posture ranges (regression = reproducibility + "prove accuracy" evidence for Q&A).

## 5. Realtime demo segment (venue)

1. Dashboard already shows pre-collected real corpus (offline).
2. Presenter clicks "send test mail" (mail to third-party test address) → agent records → chunk → `/ws/live` → flow + score update within seconds.
3. Fallback: recorded 1080p screencast of the same flow plus the corpus always ships inside the laptop app.
4. Never depends on venue network; DNS reads are enrichment only.

## 6. Guardrails

- Standard: keep mailbox credentials in `.env.local` (never in repo); weak-lab and strong live apart.
- If VPS provider blocks outbound 25, substitute: submission-port smarthost + lab-local peer containers (`lab/peers/`) — roadmap §5 risk row.
- Never claim capture of peers' servers; only our own egress/ingress boundary is captured.