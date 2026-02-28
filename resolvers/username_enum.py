"""Mass username enumeration using WhatsMyName dataset (~600 sites) via async httpx."""

import asyncio
import logging
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType

logger = logging.getLogger(__name__)

SOURCE = "username_enum"

# Module-level cache for the WhatsMyName dataset (populated on first invocation)
_wmn_sites: list[dict] | None = None
_WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

# Per-site HTTP timeout
_SITE_TIMEOUT = 10
# Max concurrent HTTP checks per invocation
_CONCURRENCY = 100


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _load_wmn_sites() -> list[dict]:
    global _wmn_sites
    if _wmn_sites is not None:
        return _wmn_sites
    try:
        r = httpx.get(_WMN_URL, timeout=30, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        _wmn_sites = data.get("sites", [])
        logger.info("Loaded %d WhatsMyName sites", len(_wmn_sites))
    except Exception as e:
        logger.error("Failed to load WhatsMyName dataset: %s", e)
        _wmn_sites = []
    return _wmn_sites


async def _check_site(
    client: httpx.AsyncClient,
    site: dict,
    username: str,
) -> dict | None:
    """Check one site. Returns hit dict if confirmed, else None."""
    uri_template = site.get("uri_check", "")
    if not uri_template:
        return None
    url = uri_template.replace("{account}", username)
    e_string = site.get("e_string", "")
    e_code = site.get("e_code", 200)
    try:
        resp = await client.get(url, timeout=_SITE_TIMEOUT, follow_redirects=True)
        code_match = resp.status_code == e_code
        body_match = e_string and e_string in resp.text
        if code_match and (not e_string or body_match):
            return {
                "site_name": site.get("name", ""),
                "url": url,
                "category": site.get("category", ""),
                "uri_pretty": site.get("uri_pretty", "").replace("{account}", username),
            }
    except Exception:
        pass
    return None


async def _extract_profile_info(client: httpx.AsyncClient, url: str) -> dict:
    """Try to scrape name/bio from a confirmed profile page."""
    try:
        from bs4 import BeautifulSoup

        resp = await client.get(url, timeout=_SITE_TIMEOUT, follow_redirects=True)
        if resp.status_code != 200:
            return {}
        soup = BeautifulSoup(resp.text, "html.parser")
        # Generic heuristics: look for og:title, og:description, name meta tags
        result: dict[str, str] = {}
        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            result["og_title"] = og_title["content"]
        og_desc = soup.find("meta", property="og:description")
        if og_desc and og_desc.get("content"):
            result["og_description"] = og_desc["content"]
        # fallback: <title>
        if "og_title" not in result and soup.title and soup.title.string:
            result["page_title"] = soup.title.string.strip()
        return result
    except Exception:
        return {}


async def _run_all_checks(username: str, sites: list[dict]) -> list[dict]:
    """Run all site checks concurrently, return confirmed hits with scraped metadata."""
    sem = asyncio.Semaphore(_CONCURRENCY)
    hits: list[dict] = []

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
        follow_redirects=True,
    ) as client:
        async def _bounded_check(site: dict) -> dict | None:
            async with sem:
                return await _check_site(client, site, username)

        results = await asyncio.gather(*[_bounded_check(s) for s in sites], return_exceptions=True)

        # Scrape profiles for hits
        profile_tasks = []
        hit_indices = []
        confirmed: list[dict] = []
        for r in results:
            if isinstance(r, dict):
                confirmed.append(r)

        async def _bounded_scrape(hit: dict) -> dict:
            async with sem:
                profile = await _extract_profile_info(client, hit["url"])
                return {**hit, **profile}

        scraped = await asyncio.gather(*[_bounded_scrape(h) for h in confirmed], return_exceptions=True)
        for r in scraped:
            if isinstance(r, dict):
                hits.append(r)

    return hits


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=20)
def enumerate_username(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    q: modal.Queue,
    d: modal.Dict,
) -> None:
    """Enumerate a username across ~600 sites via the WhatsMyName dataset."""
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return

    sites = _load_wmn_sites()
    if not sites:
        logger.warning("No WhatsMyName sites available; skipping enumeration")
        return

    node_id = _entity_key(EntityType.USERNAME.value, username)
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "enum_username", "confidence": 1.0}
    ]

    # Run async checks synchronously
    hits = asyncio.run(_run_all_checks(username, sites))

    metadata: dict[str, Any] = {
        "username": username,
        "sites_checked": len(sites),
        "hits_count": len(hits),
        "confirmed_profiles": hits,
    }

    # Write node
    d[f"{NODE_PREFIX}{node_id}"] = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    # No child entities pushed; username_enum is a leaf resolver
