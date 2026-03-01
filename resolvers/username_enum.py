"""Mass username enumeration using WhatsMyName dataset (~600 sites) via async httpx."""

import asyncio
import json
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "username_enum"

# Module-level cache for the WhatsMyName dataset (populated on first invocation)
_wmn_sites: list[dict] | None = None
_WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

# Per-site HTTP timeout
_SITE_TIMEOUT = 10
# Max concurrent HTTP checks per invocation
_CONCURRENCY = 100
# Wall-clock budget for the entire resolver; leaves ~15s margin before the
# orchestrator's 120s _RESOLVER_TIMEOUT kills the Modal .get() call.
_WALL_CLOCK_BUDGET = 105

# Distiller model — cheapest/fastest for structured extraction
_DISTILLER_MODEL = "claude-haiku-4-5-20251001"
# Max tokens to send to distiller (keeps cost low, avoids context overflow)
_DISTILLER_INPUT_TOKEN_BUDGET = 8000
# Rough chars-per-token estimate for truncation
_CHARS_PER_TOKEN = 4

# Regex patterns for follower/following counts in page text
_FOLLOWER_RE = re.compile(
    r"([\d,\.]+[KkMmBb]?)\s*(?:followers?|following|subscribers?|fans?)",
    re.IGNORECASE,
)
_JOIN_DATE_RE = re.compile(
    r"(?:joined|member since|created|registered)[:\s]+([A-Za-z0-9, ]+\d{4})",
    re.IGNORECASE,
)


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
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
        response_preview = (getattr(e, "response", None) and getattr(e.response, "text", None) or "")[:500]
        logger.error(
            "Failed to load WhatsMyName dataset (service=WhatsMyName dataset): %s; response_preview: %s",
            e,
            response_preview,
        )
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
    except Exception as e:
        logger.debug("_check_site failed for site %s url %s: %s", site.get("name"), url, e)
    return None


def _parse_follower_count(text: str) -> int | None:
    """Parse a follower count string like '1.2K' or '3,456' into an int."""
    text = text.strip().replace(",", "")
    multipliers = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}
    lower = text.lower()
    for suffix, mult in multipliers.items():
        if lower.endswith(suffix):
            try:
                return int(float(lower[:-1]) * mult)
            except ValueError:
                return None
    try:
        return int(float(text))
    except ValueError:
        return None


async def _extract_profile_info(client: httpx.AsyncClient, url: str) -> dict:
    """Aggressively scrape identity-relevant metadata from a confirmed profile page."""
    try:
        from bs4 import BeautifulSoup

        resp = await client.get(url, timeout=_SITE_TIMEOUT, follow_redirects=True)
        if resp.status_code != 200:
            return {}
        soup = BeautifulSoup(resp.text, "html.parser")
        result: dict[str, Any] = {}
        page_host = urlparse(url).netloc

        # --- Meta tags ---
        def _meta(prop: str | None = None, name: str | None = None) -> str:
            tag = None
            if prop:
                tag = soup.find("meta", property=prop)
            if not tag and name:
                tag = soup.find("meta", attrs={"name": name})
            if tag:
                content = tag.get("content", "")
                return (content or "").strip()[:500]
            return ""

        og_title = _meta(prop="og:title")
        og_desc = _meta(prop="og:description")
        og_image = _meta(prop="og:image")
        tw_title = _meta(prop="twitter:title")
        tw_desc = _meta(prop="twitter:description")
        tw_image = _meta(prop="twitter:image")
        meta_desc = _meta(name="description")
        meta_author = _meta(name="author")

        if og_title:
            result["og_title"] = og_title
        if og_desc:
            result["og_description"] = og_desc
        if og_image:
            result["og_image"] = og_image
        if tw_title:
            result["twitter_title"] = tw_title
        if tw_desc:
            result["twitter_description"] = tw_desc
        if tw_image:
            result["twitter_image"] = tw_image
        if meta_desc:
            result["meta_description"] = meta_desc
        if meta_author:
            result["meta_author"] = meta_author

        # Page title fallback
        if not og_title and soup.title and soup.title.string:
            result["page_title"] = soup.title.string.strip()[:200]

        # --- Display name heuristics ---
        display_name = ""
        name_selectors = [
            "[itemprop='name']",
            "h1.profile-name", "h1.username", "h1.displayname",
            ".profile-name", ".display-name", ".user-name", ".username",
            ".name", ".fullname", ".full-name",
            "h1", "h2",
        ]
        for sel in name_selectors:
            try:
                tag = soup.select_one(sel)
                if tag:
                    text = tag.get_text(separator=" ", strip=True)
                    if text and 2 <= len(text) <= 100:
                        display_name = text[:100]
                        break
            except Exception:
                continue
        if display_name:
            result["display_name"] = display_name

        # --- Bio/description heuristics ---
        bio_text = ""
        bio_selectors = [
            "[itemprop='description']",
            ".bio", ".biography", ".profile-bio", ".user-bio",
            ".about", ".description", ".profile-description",
            "p.bio", "div.bio",
        ]
        for sel in bio_selectors:
            try:
                tag = soup.select_one(sel)
                if tag:
                    text = tag.get_text(separator=" ", strip=True)
                    if text and len(text) >= 5:
                        bio_text = text[:500]
                        break
            except Exception:
                continue
        if bio_text:
            result["bio_text"] = bio_text

        # --- Avatar URL heuristics ---
        avatar_url = og_image or tw_image or ""
        if not avatar_url:
            avatar_classes = ["avatar", "profile-pic", "profile-image", "user-photo", "user-avatar"]
            for img in soup.find_all("img"):
                img_classes = " ".join(img.get("class") or []).lower()
                img_id = (img.get("id") or "").lower()
                if any(c in img_classes or c in img_id for c in avatar_classes):
                    src = img.get("src") or img.get("data-src") or ""
                    if src and src.startswith("http"):
                        avatar_url = src[:500]
                        break
        if avatar_url:
            result["avatar_url"] = avatar_url

        # --- Follower/following counts ---
        page_text = soup.get_text(separator=" ", strip=True)
        follower_matches = _FOLLOWER_RE.findall(page_text)
        if follower_matches:
            count = _parse_follower_count(follower_matches[0])
            if count is not None:
                result["follower_count"] = count

        # --- Join date ---
        # Try <time datetime="..."> elements first
        for time_tag in soup.find_all("time"):
            dt = time_tag.get("datetime") or time_tag.get_text(strip=True)
            if dt and re.search(r"\d{4}", dt):
                result["join_date"] = dt[:50]
                break
        if "join_date" not in result:
            m = _JOIN_DATE_RE.search(page_text)
            if m:
                result["join_date"] = m.group(1).strip()[:50]

        # --- External linked URLs ---
        # Collect rel="me" links first (highest identity signal), then other external hrefs
        external_links: list[str] = []
        seen_links: set[str] = set()

        def _add_link(href: str) -> None:
            if not href or href in seen_links:
                return
            parsed = urlparse(href)
            if parsed.scheme not in ("http", "https"):
                return
            if parsed.netloc and parsed.netloc != page_host:
                seen_links.add(href)
                external_links.append(href[:300])

        for a in soup.find_all("a", rel=True):
            rels = a.get("rel") or []
            if "me" in rels or "noopener" not in rels:
                _add_link(a.get("href", ""))

        for a in soup.find_all("a", href=True):
            if len(external_links) >= 10:
                break
            _add_link(a.get("href", ""))

        if external_links:
            result["external_links"] = external_links[:10]

        return result

    except Exception as e:
        logger.debug("_extract_profile_info failed for %s: %s", url, e)
        return {}


def _fallback_distill(raw_profiles: list[dict]) -> list[dict]:
    """Deterministic fallback distillation when the Claude call fails."""
    distilled = []
    for p in raw_profiles:
        entry: dict[str, Any] = {
            "site_name": p.get("site_name", ""),
            "display_name": (
                p.get("og_title")
                or p.get("twitter_title")
                or p.get("display_name")
                or p.get("meta_author")
                or p.get("page_title")
                or ""
            )[:120],
            "bio_snippet": (
                p.get("og_description")
                or p.get("twitter_description")
                or p.get("meta_description")
                or p.get("bio_text")
                or ""
            )[:120],
            "avatar_url": (
                p.get("og_image")
                or p.get("twitter_image")
                or p.get("avatar_url")
                or ""
            )[:300],
            "follower_count": p.get("follower_count"),
            "join_date": p.get("join_date"),
            "linked_urls": (p.get("external_links") or [])[:3],
            "identity_mismatch": False,
        }
        distilled.append(entry)
    return distilled


def _distill_profiles(raw_profiles: list[dict], username: str) -> list[dict]:
    """Call Claude Haiku to distill raw scraped profiles into structured identity fields.

    Batches all profiles into a single API call. Falls back to deterministic
    heuristics if the call fails or times out.
    """
    if not raw_profiles:
        return []

    try:
        from anthropic import Anthropic

        client = Anthropic()

        # Build a compact JSON representation of each profile for the prompt.
        # Prioritise fields with identity signal; drop empty values.
        _KEEP_KEYS = {
            "site_name", "url", "og_title", "og_description", "og_image",
            "twitter_title", "twitter_description", "twitter_image",
            "meta_description", "meta_author", "page_title",
            "display_name", "bio_text", "avatar_url",
            "follower_count", "join_date", "external_links",
        }

        compact_profiles = []
        for i, p in enumerate(raw_profiles):
            entry = {"_idx": i}
            for k in _KEEP_KEYS:
                v = p.get(k)
                if v is not None and v != "" and v != []:
                    entry[k] = v
            compact_profiles.append(entry)

        # Sort by richness (most fields first) so if we truncate we keep the best ones
        compact_profiles.sort(key=lambda x: -len(x))

        # Truncate to fit within token budget
        max_chars = _DISTILLER_INPUT_TOKEN_BUDGET * _CHARS_PER_TOKEN
        profiles_json = json.dumps(compact_profiles, ensure_ascii=False)
        if len(profiles_json) > max_chars:
            # Binary search for how many profiles fit
            lo, hi = 1, len(compact_profiles)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if len(json.dumps(compact_profiles[:mid], ensure_ascii=False)) <= max_chars:
                    lo = mid
                else:
                    hi = mid - 1
            compact_profiles = compact_profiles[:lo]
            profiles_json = json.dumps(compact_profiles, ensure_ascii=False)
            logger.info(
                "_distill_profiles: truncated to %d/%d profiles to fit token budget",
                lo, len(raw_profiles),
            )

        system_prompt = (
            "You are an OSINT identity analyst. You receive a JSON array of raw scraped "
            "profile pages for the username '{username}'. For each profile, extract only "
            "the fields that help confirm or cross-reference the person's real identity.\n\n"
            "Return a JSON array (same length as input, same order) where each element has:\n"
            "  _idx: integer (from input, for alignment)\n"
            "  display_name: string or null — the person's display name on this platform\n"
            "  bio_snippet: string or null — max 120 chars of bio/description text\n"
            "  avatar_url: string or null — URL of profile picture\n"
            "  follower_count: integer or null\n"
            "  join_date: string or null — ISO date or human-readable date\n"
            "  linked_urls: array of up to 3 strings — external URLs linked from the profile "
            "that suggest identity (personal sites, other social profiles, etc.)\n"
            "  identity_mismatch: boolean — true if display_name or bio strongly suggests "
            "this is a DIFFERENT person than the username '{username}'\n\n"
            "Rules:\n"
            "- Drop navigation links, cookie banners, generic platform boilerplate.\n"
            "- Prefer og:title/twitter:title over page_title for display_name.\n"
            "- bio_snippet must be actual self-description, not platform UI text.\n"
            "- linked_urls should point to personal sites, other social profiles, or "
            "identity-confirming pages — not platform help pages or ads.\n"
            "- Return ONLY the JSON array, no preamble."
        ).replace("{username}", username)

        message = client.messages.create(
            model=_DISTILLER_MODEL,
            system=system_prompt,
            max_tokens=2048,
            messages=[{"role": "user", "content": profiles_json}],
        )

        raw_output = message.content[0].text.strip()
        # Extract JSON array from response
        start = raw_output.find("[")
        end = raw_output.rfind("]") + 1
        if start < 0 or end <= start:
            raise ValueError("No JSON array found in distiller response")

        distilled_list = json.loads(raw_output[start:end])

        # Build a lookup by _idx so we can align with original profiles
        idx_map: dict[int, dict] = {}
        for item in distilled_list:
            if isinstance(item, dict) and "_idx" in item:
                idx_map[item["_idx"]] = item

        # Merge distilled fields back onto original profiles (preserving site_name/url/category)
        result = []
        for i, p in enumerate(raw_profiles):
            distilled = idx_map.get(i, {})
            entry: dict[str, Any] = {
                "site_name": p.get("site_name", ""),
                "display_name": distilled.get("display_name") or "",
                "bio_snippet": (distilled.get("bio_snippet") or "")[:120],
                "avatar_url": distilled.get("avatar_url") or "",
                "follower_count": distilled.get("follower_count"),
                "join_date": distilled.get("join_date"),
                "linked_urls": (distilled.get("linked_urls") or [])[:3],
                "identity_mismatch": bool(distilled.get("identity_mismatch", False)),
            }
            result.append(entry)

        logger.info(
            "_distill_profiles: distilled %d profiles via Claude Haiku",
            len(result),
        )
        return result

    except Exception as e:
        logger.warning("_distill_profiles Claude call failed, using fallback: %s", e)
        return _fallback_distill(raw_profiles)


async def _run_all_checks(username: str, sites: list[dict], deadline: float, scan_id: str = "") -> list[dict]:
    """Run site checks concurrently with a wall-clock deadline.

    Uses asyncio.wait instead of asyncio.gather so we can collect whatever
    results are ready when the deadline approaches, rather than losing
    everything if the outer timeout fires.
    """
    sem = asyncio.Semaphore(_CONCURRENCY)

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
        follow_redirects=True,
    ) as client:
        async def _bounded_check(site: dict) -> dict | None:
            async with sem:
                return await _check_site(client, site, username)

        tasks = [asyncio.ensure_future(_bounded_check(s)) for s in sites]

        remaining = max(0.0, deadline - time.monotonic())
        done, pending = await asyncio.wait(tasks, timeout=remaining)

        for t in pending:
            t.cancel()

        confirmed: list[dict] = []
        for t in done:
            try:
                r = t.result()
            except Exception:
                continue
            if isinstance(r, dict):
                confirmed.append(r)

        logger.info(
            "username_enum: %d/%d sites completed, %d pending cancelled, %d hits",
            len(done), len(sites), len(pending), len(confirmed),
        )

        write_stream_event(scan_id, "narration", {
            "message": f"enumerate_username: checked {len(done)}/{len(sites)} sites — {len(confirmed)} profile(s) found",
            "category": "resolver",
        })

        remaining = max(0.0, deadline - time.monotonic())
        if remaining < 5.0 or not confirmed:
            return confirmed

        # --- Aggressive profile scraping phase ---
        write_stream_event(scan_id, "narration", {
            "message": f"enumerate_username: scraping metadata from {len(confirmed)} confirmed profile(s)...",
            "category": "resolver",
        })

        async def _bounded_scrape(hit: dict) -> dict:
            async with sem:
                profile = await _extract_profile_info(client, hit["url"])
                # Merge hit fields into profile so distiller has site_name/url
                return {**hit, **profile}

        scrape_tasks = [asyncio.ensure_future(_bounded_scrape(h)) for h in confirmed]
        # Reserve ~15s for the distiller Claude call after scraping
        scrape_budget = max(0.0, remaining - 15.0)
        scrape_done, scrape_pending = await asyncio.wait(scrape_tasks, timeout=scrape_budget)

        for t in scrape_pending:
            t.cancel()

        # Build raw_scraped in confirmed-index order so distiller _idx aligns correctly
        raw_scraped: list[dict] = []
        task_results: dict[int, dict] = {}
        for i, t in enumerate(scrape_tasks):
            if t in scrape_done:
                try:
                    r = t.result()
                except Exception:
                    r = None
                if isinstance(r, dict):
                    task_results[i] = r

        for i, hit in enumerate(confirmed):
            raw_scraped.append(task_results.get(i, hit))

    # --- Distillation phase (synchronous Claude call, outside async context) ---
    remaining = max(0.0, deadline - time.monotonic())
    if remaining >= 3.0 and raw_scraped:
        write_stream_event(scan_id, "narration", {
            "message": f"enumerate_username: distilling {len(raw_scraped)} profile(s) with AI...",
            "category": "resolver",
        })
        distilled = _distill_profiles(raw_scraped, username)
    else:
        logger.info("_run_all_checks: no time for distillation, using fallback")
        distilled = _fallback_distill(raw_scraped)

    # Merge distilled metadata back onto the confirmed hit list (preserving url/category)
    hits: list[dict] = []
    for i, hit in enumerate(confirmed):
        distilled_entry = distilled[i] if i < len(distilled) else {}
        hits.append({**hit, **distilled_entry})

    return hits


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=20)
def enumerate_username(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Enumerate a username across ~600 sites via the WhatsMyName dataset."""
    wall_start = time.monotonic()

    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
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

    write_stream_event(scan_id, "narration", {
        "message": f"enumerate_username: checking {len(sites)} sites for '{username}'...",
        "category": "resolver",
    })

    deadline = wall_start + _WALL_CLOCK_BUDGET
    hits = asyncio.run(_run_all_checks(username, sites, deadline, scan_id=scan_id))

    metadata: dict[str, Any] = {
        "username": username,
        "sites_checked": len(sites),
        "hits_count": len(hits),
        "confirmed_profiles": hits,
        "partial": time.monotonic() > deadline - 5,
    }

    # Write node
    node_payload = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }
    try:
        d[f"{NODE_PREFIX}{node_id}"] = node_payload
    except Exception as e:
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="enumerate_username",
            entity_key=node_id,
            error=str(e),
            service="username_enum_write",
            data_preview=str(node_payload)[:500],
        )
        return
    write_stream_event(scan_id, "node", node_payload)

    try:
        d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    except Exception as e:
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="enumerate_username",
            entity_key=node_id,
            error=str(e),
            service="username_enum_write",
            data_preview=str(edges_batch)[:500],
        )
        return
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

    # Expand each confirmed profile hit into its own graph node and edge
    platform_edges: list[dict[str, Any]] = []
    for hit in hits:
        if hit.get("identity_mismatch", False):
            continue
        site_name = (hit.get("site_name") or "").strip()
        platform_node_id = f"platform:{site_name.lower()}:{username.lower()}"
        platform_node_payload = {
            "id": platform_node_id,
            "type": "platform_profile",
            "value": hit.get("url", ""),
            "metadata": {
                "site_name": hit.get("site_name", ""),
                "url": hit.get("url", ""),
                "category": hit.get("category", ""),
                "display_name": hit.get("display_name", ""),
                "bio_snippet": hit.get("bio_snippet", ""),
                "avatar_url": hit.get("avatar_url", ""),
                "follower_count": hit.get("follower_count"),
                "join_date": hit.get("join_date"),
                "linked_urls": hit.get("linked_urls") or [],
                "identity_mismatch": hit.get("identity_mismatch", False),
            },
            "depth": depth + 1,
        }
        try:
            d[f"{NODE_PREFIX}{platform_node_id}"] = platform_node_payload
        except Exception as e:
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="enumerate_username",
                entity_key=node_id,
                error=str(e),
                service="username_enum_write",
                data_preview=str(platform_node_payload)[:500],
            )
            continue
        write_stream_event(scan_id, "node", platform_node_payload)
        platform_edges.append({
            "source": node_id,
            "target": platform_node_id,
            "relationship": "found_on_platform",
            "confidence": 1.0,
        })
    if platform_edges:
        try:
            d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = platform_edges
        except Exception as e:
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="enumerate_username",
                entity_key=node_id,
                error=str(e),
                service="username_enum_write",
                data_preview=str(platform_edges)[:500],
            )
        else:
            for edge in platform_edges:
                write_stream_event(scan_id, "edge", edge)
    # No child entities pushed; username_enum is a leaf resolver
