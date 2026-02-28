# OSINT Digital Footprint Reconstructor (Modal)

Runs on Modal as a parallel graph traversal: seed identifier → Queue + Dict → resolvers discover linked identities → graph built and stored.

## Setup

1. Install Modal and log in: `pip install modal && modal setup`
2. Create a secret named `osint-keys` with your API keys (e.g. `GITHUB_TOKEN` for the username resolver). In Modal dashboard: Secrets → Create → name `osint-keys`, add env vars. EmailRep.io is used via the official `emailrep` Python library and works without an API key; for higher rate limits, set `EMAILREP_KEY` in `osint-keys` once your key is approved. LeakCheck breach lookups use the free public API by default; set `LEAKCHECK_APIKEY` (or `LEAKCHECK_KEY`) in `osint-keys` to use the Pro API v2 for higher limits and additional data.

## Run

From this directory (`osint-recon/`):

```bash
modal serve app.py
```

This starts the FastAPI app. Use the returned URL for:

- **POST /scan** – Start a scan. Body: `{"seed": {"type": "username", "value": "octocat"}, "config": null}`. Returns `{"scan_id": "..."}`.
- **GET /scan/{scan_id}/status** – Status: `running`, `completed`, or `failed`; optional `entities_seen`, `depth_reached`, `error`.
- **GET /scan/{scan_id}/graph** – Full graph JSON: `{"nodes": [...], "edges": [...]}` (404 if not found, 202 if still running).

Phase 1 includes only the **username** resolver (GitHub API). Other resolvers and LLM extraction are Phase 2.
