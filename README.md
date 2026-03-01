# Phantom — OSINT Intelligence Platform

**Phantom** is an autonomous OSINT (Open Source Intelligence) platform that reconstructs digital footprints from a single seed identifier. Given a username, email, phone number, domain, or crypto wallet address, Phantom's AI-driven planner–analyst loop discovers linked identities across hundreds of services, correlates them into a unified graph, and produces a structured intelligence report — all in real time.

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- **Autonomous AI Agent Loop** — A Claude-powered planner selects investigation tools while an analyst synthesizes findings, iterating until the digital footprint is fully mapped.
- **600+ Site Username Enumeration** — Checks username presence across ~600 platforms using the WhatsMyName dataset with async HTTP.
- **Multi-Source Resolvers** — Dedicated resolvers for GitHub profiles, email verification (Kickbox, Hunter, Gravatar, HIBP, EmailRep), domain intelligence (crt.sh, WHOIS, DNS, SecurityTrails), breach databases (Dehashed, LeakCheck, BreachDirectory), social platforms (Reddit, Keybase, Hacker News, Stack Overflow, PGP), phone lookups (Numverify, Veriphone), and crypto wallets (Etherscan, Blockchain.com).
- **GPU-Accelerated Entity Extraction** — Post-scan, a Qwen2.5-1.5B model running on an A10G GPU extracts additional emails, usernames, and domains from unstructured node metadata.
- **Identity Correlation** — GPU-backed scoring links nodes that likely belong to the same person, with breach correlation matching shared password hashes, IPs, and phone numbers.
- **Real-Time Streaming** — Server-Sent Events (SSE) push nodes, edges, analyst briefs, planner actions, and status updates to the frontend as the investigation unfolds.
- **Interactive Graph Visualization** — D3.js force-directed graph with color-coded node types, correlation edges, identity cluster hulls, tooltips, and JSON export.
- **Wave Pipelining** — An in-flight pool harvests completed resolvers without blocking, so the planner can continue with partial results.
- **Scan Control** — Start, monitor, and cancel scans via REST API.
- **Intelligence Reports** — Auto-generated reports covering identity profile, risk assessment, credential exposure, correlations, and recommendations.

## Architecture

```
Seed Identifier
       │
       ▼
   ┌────────┐     ┌──────────┐     ┌───────────┐
   │ Planner│────▶│ Resolvers│────▶│  Analyst  │
   │(Claude)│◀────│(parallel)│     │ (Claude)  │
   └────────┘     └──────────┘     └───────────┘
       │               │                 │
       │          ┌────▼────┐            │
       │          │  Modal  │            │
       │          │  Dict   │◀───────────┘
       │          └────┬────┘
       │               │
       ▼               ▼
   ┌────────┐    ┌───────────┐    ┌──────────┐
   │  GPU   │    │   Graph   │    │  Report  │
   │Extract │───▶│  Builder  │───▶│Generator │
   └────────┘    └───────────┘    └──────────┘
                       │
                       ▼
                 ┌───────────┐
                 │ Frontend  │
                 │(D3 + SSE) │
                 └───────────┘
```

1. A **seed** (username, email, etc.) is submitted via the API.
2. The **Planner** (Claude Sonnet) selects which resolver tools to run based on accumulated briefs.
3. **Resolvers** execute in parallel on Modal, writing discovered entities and edges to a per-scan Dict.
4. The **Analyst** (Claude Sonnet) compresses raw resolver output into structured briefs for the next planning cycle.
5. **Post-processing** runs GPU entity extraction, breach correlation, and identity correlation.
6. A **Report Generator** produces the final intelligence report over the completed graph.
7. The **Frontend** receives live updates via SSE and renders an interactive force-directed graph.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Compute | [Modal](https://modal.com) (serverless CPU + GPU) |
| API | FastAPI |
| LLM | Anthropic Claude (Sonnet 4, Haiku) |
| GPU Inference | PyTorch, Transformers, Qwen2.5-1.5B-Instruct on A10G |
| Graph | NetworkX |
| HTTP | requests, httpx, aiohttp |
| Data Validation | Pydantic v2 |
| Frontend | Vanilla JS, D3.js v7, Server-Sent Events |

## Project Structure

```
├── app.py                  # Modal app definition, image, secrets
├── api.py                  # FastAPI endpoints
├── orchestrator.py         # Planner–Analyst scan loop with InFlightPool
├── models.py               # Pydantic data models
├── graph.py                # NetworkX graph construction
├── stream.py               # SSE event writer
├── scan_log.py             # Per-scan activity logging
├── agent/
│   ├── planner.py          # Planner agent (tool selection)
│   ├── analyst.py          # Analyst agent (brief synthesis)
│   ├── tools.py            # Anthropic tool schemas for resolvers
│   ├── report.py           # Intelligence report generator
│   └── state.py            # Graph state tracking and diffs
├── resolvers/
│   ├── username.py         # GitHub profile resolver
│   ├── username_enum.py    # WhatsMyName 600+ site enumeration
│   ├── email.py            # Email verification and enrichment
│   ├── domain.py           # Domain intelligence (crt.sh, WHOIS, DNS)
│   ├── breach.py           # Breach database lookups
│   ├── social.py           # Social platform resolvers
│   ├── phone.py            # Phone number lookups
│   ├── wallet.py           # Crypto wallet analysis
│   └── identity_correlator.py  # GPU-backed identity matching
├── inference/
│   └── extractor.py        # GPU entity extractor (Qwen2.5-1.5B)
└── frontend/
    └── index.html          # Single-page app (D3 graph + SSE)
```

## Setup

### Prerequisites

- Python 3.12+
- A [Modal](https://modal.com) account
- An [Anthropic](https://console.anthropic.com) API key

### Installation

```bash
git clone https://github.com/drPod/Phantom.git
cd Phantom
pip install -r requirements.txt
modal setup
```

### API Keys

Create a Modal secret named `osint-keys` with your API keys. In the Modal dashboard: **Secrets → Create → name `osint-keys`**, then add the relevant environment variables:

| Variable | Service | Required |
|----------|---------|----------|
| `ANTHROPIC_API_KEY` | Anthropic Claude | Yes |
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

Most resolvers degrade gracefully when optional keys are missing — they simply skip that data source.

## Usage

### Start the Server

```bash
modal serve app.py
```

This deploys the FastAPI app on Modal. Use the returned URL to access the API and frontend.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Start a scan. Body: `{"seed": {"type": "username", "value": "octocat"}}` |
| `GET` | `/scan/{id}/status` | Scan status: `running`, `completed`, or `failed` |
| `GET` | `/scan/{id}/graph` | Full graph JSON (`nodes` + `edges`) |
| `GET` | `/scan/{id}/stream` | SSE stream of live scan events |
| `GET` | `/scan/{id}/report` | Generated intelligence report |
| `GET` | `/scan/{id}/log` | Activity log |
| `POST` | `/scan/{id}/stop` | Cancel a running scan |

### Frontend

Open the frontend `index.html` in a browser (or use the served URL) to access the interactive UI with:

- Real-time graph visualization as the scan progresses
- Node details sidebar with full metadata
- Agent transcript panel showing planner/analyst reasoning
- Debug panel with resolver tracking and activity feed
- Downloadable intelligence report

## Disclaimer

This tool is intended for **authorized security research, penetration testing, and OSINT investigations only**. Users are responsible for ensuring compliance with all applicable laws and regulations. Do not use this tool to access systems or data without proper authorization.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
