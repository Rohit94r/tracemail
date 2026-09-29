# Raven (SecureMailScope) — SIH26159

**Passive, air-gapped cryptographic security posture assessment platform for enterprise email infrastructure.**

Ingests raw `.pcap` / `.pcapng` network captures, reassembles SMTP/IMAP/POP3 protocol dialogs, executes a 6-class STARTTLS state machine, and computes confidence-bounded RFC security posture ratings with court-grade cryptographic provenance without sending a single active probe packet.

---

## Project Structure

Everything is self-contained inside this directory:

```
platform/
├── backend/                  # Python FastAPI Backend Engine
│   ├── app/
│   │   ├── main.py           # FastAPI ASGI entry & WebSocket feed
│   │   ├── config.py         # Pinned rubric weights & Bayesian priors
│   │   ├── models.py         # Pydantic schemas & data models
│   │   ├── db.py             # SQLite database helper
│   │   ├── state.py          # Dynamic session & PCAP upload cache
│   │   ├── modules/          # Core cryptographic analysis modules
│   │   │   ├── ingest.py     # Scapy packet parser & TCP reassembly
│   │   │   ├── rules.py      # Deterministic RFC rule catalog
│   │   │   ├── posture.py    # 0–100 score with 95% Confidence Intervals
│   │   │   └── radar.py      # Bayesian Downgrade Radar (P(strip))
│   │   └── api/              # REST endpoints (health, captures, findings, mx, graph, reports, ask, lens, integrity)
│   ├── tests/
│   │   └── test_engine.py    # Automated pytest unit test suite
│   ├── requirements.txt      # Python dependencies
│   └── pyproject.toml
├── corpus/                   # Reference Test Scenarios & Oracles
│   ├── scenarios/            # Frozen .pcap captures (stripped, weak-cipher, etc.)
│   └── generate_corpus.py    # Synthetic PCAP generation script
├── scripts/
│   ├── dev.mjs               # Unified dev orchestrator (boots backend + frontend)
│   └── setup.mjs             # Dependency verifier & DB initializer
├── app/                      # Next.js 16 App Router
│   ├── page.tsx              # Research & product landing page
│   └── dashboard/            # 9-Screen Security Console
│       ├── page.tsx          # Screen 1: Passive Ingestion & Pipeline Runner
│       ├── posture/          # Screen 2: Confidence-Bounded Posture Heatmap
│       ├── graph/            # Screen 3: Cross-Hop Delivery Topology Graph
│       ├── findings/         # Screen 4: Risk Table & Packet Byte Drawer
│       ├── reports/          # Screen 5: Signed Audit Reports & MTA Playbooks
│       ├── replay/           # Screen 6: Packet Forensic Stream Replay
│       ├── ask/              # Screen 7: Grounded AI Forensic Assistant (RAG)
│       ├── lens/             # Screen 8: Attack Path Threat Forecasting
│       └── integrity/        # Screen 9: Tamper-Proof SHA-256 Manifest
├── components/               # UI components, layout shell & DashboardContext
└── public/                   # Custom protocol SVGs, logos, and icons
```

---

## Quickstart

### 1. Install & Launch Everything

```bash
pnpm dev
```

Running `pnpm dev` automatically:
1. Verifies/installs any missing Python or Node dependencies.
2. Cleans up ports `8001` and `3000` if previously occupied.
3. Starts the **FastAPI Backend** on `http://0.0.0.0:8001` with hot-reloading.
4. Starts the **Next.js Frontend** on `http://localhost:3000`.

- **Frontend Application**: [http://localhost:3000](http://localhost:3000)
- **Dashboard Console**: [http://localhost:3000/dashboard](http://localhost:3000/dashboard)
- **FastAPI Interactive API Docs**: [http://localhost:8001/docs](http://localhost:8001/docs)

---

## Available Scripts

| Command | Description |
|---|---|
| `pnpm dev` | Starts both Python FastAPI and Next.js concurrently |
| `pnpm dev:frontend` | Starts only the Next.js frontend (`localhost:3000`) |
| `pnpm dev:backend` | Starts only the FastAPI backend (`localhost:8001`) |
| `pnpm test` | Runs the Python test suite against frozen `.pcap` corpus files |
| `pnpm lint` | Runs ESLint across all TypeScript/JavaScript files |
| `pnpm build` | Compiles optimized Next.js static production bundles |
| `pnpm setup` | Verifies Python environment and initializes SQLite evidence database |
