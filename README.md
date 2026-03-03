# Phantom

**Autonomous OSINT intelligence platform.** Give it a username, email, phone number, domain, or crypto wallet — it maps the entire digital footprint in real time.

An AI planner-analyst loop drives the investigation: Claude selects which tools to run, resolvers execute in parallel across 600+ sites and breach databases, and a GPU post-processor extracts hidden connections. Results stream live to an interactive graph in the browser.

![License](https://img.shields.io/badge/license-MIT-blue.svg)

https://github.com/user-attachments/assets/placeholder

## How It Works

```
Seed (username / email / phone / domain / wallet)
       │
       ▼
┌─────────────┐     ┌────────────────┐     ┌────────────┐
│   Planner   │────▶│   Resolvers    │────▶│  Analyst   │
│  (Claude)   │◀────│  (parallel)    │     │  (Claude)  │
└─────────────┘     └────────────────┘     └────────────┘
       │                    │                     │
       │          ┌────────▼────────┐            │
       │          │   Modal Dict    │◀───────────┘
       │          │  (shared state) │
       │          └────────┬────────┘
       ▼                   ▼
┌─────────────┐     ┌────────────┐     ┌────────────┐
│  GPU Entity │────▶│   Graph    │────▶│  Report    │
│  Extractor  │     │  Builder   │     │ Generator  │
└─────────────┘     └────────────┘     └────────────┘
                          │
                          ▼
                    ┌────────────┐
                    │  Frontend  │
                    │ (D3 + SSE) │
                    └────────────┘
```

1. A **seed entity** is submitted via the API or frontend.
2. The **Planner** (Claude Sonnet) picks which resolver tools to run based on accumulated briefs.
3. **Resolvers** execute concurrently on Modal, writing discovered entities and edges to a per-scan Dict.
4. The **Analyst** (Claude Sonnet) compresses raw output into structured briefs for the next planning cycle.
5. The loop repeats — the planner reads the brief, spawns more resolvers, harvests results without blocking.
6. **GPU post-processing** runs entity extraction (Qwen 1.5B on A10G), breach correlation, and identity correlation.
7. A **Report Generator** produces the final intelligence report.
8. The **Frontend** receives live updates via SSE and renders an interactive force-directed graph.

## Features

**Intelligence Gathering**
- 600+ site username enumeration (WhatsMyName dataset, async)
- Email enrichment — Hunter.io, EmailRep, Gravatar, HIBP, Kickbox
- Domain intelligence — crt.sh, WHOIS, DNS, SecurityTrails
- Breach databases — Dehashed v2, LeakCheck, BreachDirectory
- Social platforms — Reddit, Keybase, Hacker News, Stack Overflow, PGP
- Phone lookups — Numverify, Veriphone
- Crypto wallets — Etherscan (ETH), Blockchain.com (BTC)

**AI Agent Loop**
- Claude-powered planner selects investigation tools; analyst synthesizes findings
- Wave pipelining — completed resolvers are harvested without blocking the planner
- Parallel tool calls — all selected resolvers spawn concurrently

**GPU Post-Processing**
- Qwen2.5-1.5B on A10G extracts emails, usernames, domains from unstructured metadata
- Identity correlation scores cross-platform profiles (emits `likely_same_person` edges at >= 0.75 confidence)
- Breach correlation matches shared password hashes, IPs, and phone numbers

**Frontend**
- D3.js force-directed graph with color-coded node types and correlation edges
- Real-time streaming via SSE as the investigation unfolds
- Agent transcript panel showing planner/analyst reasoning
- Downloadable intelligence reports and graph JSON export

## Tech Stack

| Layer | Technology |
|-------|------------|
| Compute | [Modal](https://modal.com) — serverless CPU + A10G GPU |
| API | FastAPI (ASGI) |
| LLM | Claude Sonnet 4.6 (planner/analyst), Haiku 4.5 (distiller) |
| GPU Inference | Qwen2.5-1.5B-Instruct via PyTorch + Transformers |
| Graph | NetworkX |
| Frontend | Vanilla JS, D3.js v7, Server-Sent Events |
| Data | Pydantic v2, Modal Dict/Queue |

## Project Structure

```
├── app.py                     # Modal app, image, secrets
├── api.py                     # FastAPI endpoints
├── orchestrator.py            # Planner–Analyst loop, InFlightPool
├── models.py                  # Pydantic data models
├── graph.py                   # NetworkX graph build/serialize
├── stream.py                  # SSE event writer
├── scan_log.py                # Per-scan activity logging
├── agent/
│   ├── planner.py             # Planner agent (tool selection)
│   ├── analyst.py             # Analyst agent (brief synthesis)
│   ├── tools.py               # Resolver tool schemas
│   ├── report.py              # Intelligence report generator
│   └── state.py               # Graph state tracking
├── resolvers/
│   ├── username.py            # GitHub profile
│   ├── username_enum.py       # WhatsMyName 600+ sites
│   ├── email.py               # Email verification & enrichment
│   ├── domain.py              # Domain intel (crt.sh, WHOIS, DNS)
│   ├── breach.py              # Breach database lookups
│   ├── social.py              # Reddit, Keybase, HN, SO, PGP
│   ├── phone.py               # Phone number lookups
│   ├── wallet.py              # Crypto wallet analysis
│   └── identity_correlator.py # Identity matching
├── inference/
│   └── extractor.py           # GPU entity extractor (Qwen2.5-1.5B)
├── telemetry/
│   ├── exporter.py            # Telemetry collection
│   ├── evaluator.py           # Scan scoring
│   └── proposer.py            # Improvement proposals
└── frontend/
    └── index.html             # Single-page app (D3 graph + SSE)
```

## Setup

### Prerequisites

- Python 3.12+
- A [Modal](https://modal.com) account
- An [Anthropic](https://console.anthropic.com) API key

### Install

```bash
git clone https://github.com/drPod/Phantom.git
cd Phantom
pip install -r requirements.txt
modal setup
```

### API Keys

Create a Modal secret named `osint-keys` with your API keys:

| Variable | Service | Required |
|----------|---------|----------|
| `ANTHROPIC_API_KEY` | Anthropic Claude | **Yes** |
| `GITHUB_TOKEN` | GitHub API | Recommended |
| `HUNTER_KEY` | Hunter.io | Optional |
| `EMAILREP_KEY` | EmailRep.io | Optional |
| `LEAKCHECK_APIKEY` | LeakCheck Pro | Optional |
| `WHOISXML_KEY` | WhoisXML API | Optional |
| `SECURITYTRAILS_KEY` | SecurityTrails | Optional |
| `NUMVERIFY_KEY` | Numverify | Optional |
| `VERIPHONE_KEY` | Veriphone | Optional |
| `ETHERSCAN_KEY` | Etherscan | Optional |
| `DEHASHED_KEY` | Dehashed | Optional |

Resolvers degrade gracefully when optional keys are missing — they skip that data source.

### Deploy

```bash
modal deploy app.py
```

### Local Dev

```bash
modal serve app.py
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Start a scan |
| `GET` | `/scan/{id}/status` | Scan status |
| `GET` | `/scan/{id}/graph` | Full graph JSON |
| `GET` | `/scan/{id}/events` | Poll for live events |
| `GET` | `/scan/{id}/stream` | SSE stream |
| `GET` | `/scan/{id}/report` | Intelligence report |
| `GET` | `/scan/{id}/log` | Activity log |
| `POST` | `/scan/{id}/stop` | Cancel a scan |

### Start a Scan

```bash
curl -X POST https://your-modal-url/scan \
  -H "Content-Type: application/json" \
  -d '{"seed": {"type": "username", "value": "torvalds"}}'
```

### Demo Mode

```bash
curl -X POST https://your-modal-url/scan \
  -H "Content-Type: application/json" \
  -d '{"seed": {"type": "username", "value": "torvalds"}, "demo_mode": true}'
```

Demo mode caps at depth 1, 50 entities, 3 min timeout — finishes in ~2 minutes.

## Disclaimer

This tool is for **authorized security research, penetration testing, and OSINT investigations only**. Users are responsible for compliance with all applicable laws and regulations. Do not use this tool to access systems or data without proper authorization.

## License

MIT — see [LICENSE](LICENSE).
