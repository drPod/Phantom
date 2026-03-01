"""Social resolver: deep analysis across Reddit, Keybase, Hacker News,
Stack Overflow, and PGP key servers.

Reddit: paginates full comment + post history, then uses a Claude Haiku
instance to compress the raw data into structured intelligence (interests,
profession, location, interaction partners, emails, URLs).

Keybase: fetches linked proofs and verifies each proof URL is reachable.

Hacker News: profile + paginated story/comment history via hn.algolia.com.

Stack Overflow: user search by display name, top tags, cross-site accounts.

PGP: keys.openpgp.org search (unchanged from prior version).
"""

import json
import logging
import re
import time
import uuid
from collections import Counter
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

SOURCE = "social_resolver"
_SUMMARIZER_MODEL = "claude-haiku-4-5-20251001"

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_URL_RE = re.compile(r"https?://[^\s\)\]>\"']+")
_REDDIT_UA = {"User-Agent": "osint-recon/1.0"}

_REDDIT_PAGE_LIMIT = 10
_REDDIT_PER_PAGE = 100
_REDDIT_PAGE_DELAY = 1.0

_HN_PAGE_LIMIT = 5
_HN_PER_PAGE = 100
_HN_PAGE_DELAY = 0.5


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _extract_emails(text: str) -> set[str]:
    return {m.lower() for m in _EMAIL_RE.findall(text)}


def _extract_urls(text: str) -> set[str]:
    raw = _URL_RE.findall(text)
    cleaned: set[str] = set()
    for u in raw:
        u = u.rstrip(".,;:!?)")
        if len(u) > 10:
            cleaned.add(u)
    return cleaned


def _log_service_error(
    scan_id: str, node_id: str, service: str, exc: Exception,
) -> None:
    response_preview = (
        getattr(getattr(exc, "response", None), "text", None) or ""
    )[:500]
    logger.warning("%s failed for %s: %s", service, node_id, exc)
    log_scan_event(
        scan_id,
        "resolver_failed",
        resolver="resolve_social",
        entity_key=node_id,
        error=str(exc),
        service=service,
        response_preview=response_preview,
    )


# ---------------------------------------------------------------------------
# Reddit helpers
# ---------------------------------------------------------------------------

def _paginate_reddit_listing(
    username: str, listing: str, max_pages: int = _REDDIT_PAGE_LIMIT,
) -> list[dict[str, Any]]:
    """Paginate /user/{username}/{listing}.json, returning all item dicts."""
    items: list[dict[str, Any]] = []
    after: str | None = None
    for _ in range(max_pages):
        params: dict[str, str] = {"limit": str(_REDDIT_PER_PAGE), "raw_json": "1"}
        if after:
            params["after"] = after
        r = httpx.get(
            f"https://www.reddit.com/user/{username}/{listing}.json",
            headers=_REDDIT_UA,
            params=params,
            timeout=15,
            follow_redirects=True,
        )
        if r.status_code != 200:
            break
        body = r.json().get("data", {})
        children = body.get("children", [])
        if not children:
            break
        for child in children:
            items.append(child.get("data", {}))
        after = body.get("after")
        if not after:
            break
        time.sleep(_REDDIT_PAGE_DELAY)
    return items


def _build_reddit_analysis_payload(
    comments: list[dict[str, Any]],
    posts: list[dict[str, Any]],
    username: str,
) -> dict[str, Any]:
    """Pre-process raw Reddit data into a structured blob for Claude."""
    subreddit_counts: Counter[str] = Counter()
    all_emails: set[str] = set()
    all_urls: set[str] = set()
    u_mention_counts: Counter[str] = Counter()
    sample_comments: list[dict[str, str]] = []

    for c in comments:
        sub = c.get("subreddit", "")
        if sub:
            subreddit_counts[sub] += 1
        body = c.get("body", "")
        all_emails |= _extract_emails(body)
        all_urls |= _extract_urls(body)
        for um in re.findall(r"u/([A-Za-z0-9_\-]{3,20})", body):
            if um.lower() != username.lower():
                u_mention_counts[um] += 1
        if len(sample_comments) < 200:
            sample_comments.append({
                "subreddit": sub,
                "body": body[:500],
                "score": str(c.get("score", 0)),
            })

    for p in posts:
        sub = p.get("subreddit", "")
        if sub:
            subreddit_counts[sub] += 1
        text = " ".join(filter(None, [
            p.get("title", ""),
            p.get("selftext", ""),
            p.get("url", ""),
        ]))
        all_emails |= _extract_emails(text)
        all_urls |= _extract_urls(text)
        for um in re.findall(r"u/([A-Za-z0-9_\-]{3,20})", text):
            if um.lower() != username.lower():
                u_mention_counts[um] += 1

    return {
        "total_comments": len(comments),
        "total_posts": len(posts),
        "subreddit_counts": dict(subreddit_counts.most_common(30)),
        "sample_comments": sample_comments[:200],
        "all_emails": sorted(all_emails)[:50],
        "all_urls": sorted(all_urls)[:100],
        "u_mention_counts": dict(u_mention_counts.most_common(20)),
    }


_REDDIT_ANALYSIS_PROMPT = """\
You are an OSINT analyst. Analyze this Reddit user's activity data and return
ONLY a JSON object (no markdown, no explanation) with these fields:

{
  "inferred_interests": ["topic1", "topic2", ...],
  "inferred_profession": "best guess or null",
  "inferred_location": "best guess or null",
  "notable_comments": ["comment excerpt revealing identity info", ...],
  "identity_signals": ["any real-name, employer, school, or personal detail found"]
}

RULES:
- inferred_interests: derive from subreddit distribution, max 10 items
- inferred_profession: look at technical subreddits, job-related comments
- inferred_location: city/region subreddits (r/nyc, r/london), timezone refs, explicit mentions
- notable_comments: max 5, only those revealing personal/identity info
- identity_signals: real names, employers, schools, personal URLs — max 10
- If insufficient data for a field, use null or empty list
- Return ONLY valid JSON, nothing else"""


def _analyze_reddit_with_claude(
    payload: dict[str, Any], username: str,
) -> dict[str, Any]:
    """Call Claude Haiku to compress Reddit data into structured intelligence."""
    from anthropic import Anthropic
    client = Anthropic()
    user_content = (
        f"Reddit username: {username}\n\n"
        f"SUBREDDIT DISTRIBUTION (top 30):\n{json.dumps(payload['subreddit_counts'])}\n\n"
        f"U/ MENTION COUNTS (interaction partners):\n{json.dumps(payload['u_mention_counts'])}\n\n"
        f"SAMPLE COMMENTS ({len(payload['sample_comments'])} of {payload['total_comments']} total):\n"
        f"{json.dumps(payload['sample_comments'][:100], ensure_ascii=False)}\n\n"
        f"EMAILS FOUND:\n{json.dumps(payload['all_emails'])}\n\n"
        f"URLS FOUND ({len(payload['all_urls'])} total, showing first 50):\n"
        f"{json.dumps(sorted(payload['all_urls'])[:50])}"
    )
    try:
        msg = client.messages.create(
            model=_SUMMARIZER_MODEL,
            max_tokens=2048,
            system=_REDDIT_ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        text = msg.content[0].text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        return json.loads(text)
    except Exception as e:
        logger.warning("Reddit Claude analysis failed for %s: %s", username, e)
        return {}


# ---------------------------------------------------------------------------
# Hacker News helpers
# ---------------------------------------------------------------------------

def _fetch_hn_profile(username: str) -> dict[str, Any] | None:
    try:
        r = httpx.get(
            f"http://hn.algolia.com/api/v1/users/{username}",
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _paginate_hn_items(username: str) -> list[dict[str, Any]]:
    """Fetch all HN stories + comments by author via Algolia search."""
    items: list[dict[str, Any]] = []
    for page in range(_HN_PAGE_LIMIT):
        try:
            r = httpx.get(
                "http://hn.algolia.com/api/v1/search_by_date",
                params={
                    "tags": f"author_{username}",
                    "hitsPerPage": str(_HN_PER_PAGE),
                    "page": str(page),
                },
                timeout=15,
            )
            if r.status_code != 200:
                break
            data = r.json()
            hits = data.get("hits", [])
            if not hits:
                break
            items.extend(hits)
            if page + 1 >= data.get("nbPages", 0):
                break
        except Exception:
            break
        time.sleep(_HN_PAGE_DELAY)
    return items


def _process_hn_items(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract structured data from HN items."""
    stories = [i for i in items if "story" in (i.get("_tags") or [])]
    comments = [i for i in items if "comment" in (i.get("_tags") or [])]

    all_emails: set[str] = set()
    all_urls: set[str] = set()
    domain_counts: Counter[str] = Counter()

    for item in items:
        text = " ".join(filter(None, [
            item.get("title") or "",
            item.get("story_text") or "",
            item.get("comment_text") or "",
            item.get("url") or "",
        ]))
        all_emails |= _extract_emails(text)
        all_urls |= _extract_urls(text)
        url = item.get("url")
        if url:
            try:
                host = urlparse(url).hostname or ""
                if host and "." in host:
                    domain_counts[host] += 1
            except Exception:
                pass

    return {
        "story_count": len(stories),
        "comment_count": len(comments),
        "top_domains": dict(domain_counts.most_common(15)),
        "extracted_emails": sorted(all_emails)[:20],
        "extracted_urls": sorted(all_urls)[:30],
    }


# ---------------------------------------------------------------------------
# Stack Overflow helpers
# ---------------------------------------------------------------------------

_SO_BASE = "https://api.stackexchange.com/2.3"


def _search_so_user(username: str) -> dict[str, Any] | None:
    """Find a Stack Overflow user by display name (exact substring match)."""
    try:
        r = httpx.get(
            f"{_SO_BASE}/users",
            params={
                "inname": username,
                "site": "stackoverflow",
                "pagesize": "5",
                "order": "desc",
                "sort": "reputation",
            },
            timeout=15,
        )
        if r.status_code != 200:
            return None
        items = r.json().get("items", [])
        for user in items:
            if (user.get("display_name") or "").lower() == username.lower():
                return user
        return items[0] if items else None
    except Exception:
        return None


def _fetch_so_top_tags(user_id: int) -> list[dict[str, Any]]:
    try:
        r = httpx.get(
            f"{_SO_BASE}/users/{user_id}/top-question-tags",
            params={"site": "stackoverflow"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("items", [])[:20]
    except Exception:
        pass
    return []


def _fetch_so_associated(user_id: int) -> list[dict[str, Any]]:
    try:
        r = httpx.get(
            f"{_SO_BASE}/users/{user_id}/associated",
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("items", [])
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Keybase helpers
# ---------------------------------------------------------------------------

def _verify_keybase_proof(url: str) -> bool:
    """Check if a Keybase proof URL is reachable (200 OK)."""
    try:
        r = httpx.head(url, timeout=5, follow_redirects=True)
        return r.status_code == 200
    except Exception:
        try:
            r = httpx.get(url, timeout=5, follow_redirects=True)
            return r.status_code == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

@app.function(image=image, secrets=[osint_secret], timeout=300)
@modal.concurrent(max_inputs=10)
def resolve_social(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Deep social presence analysis: Reddit, Keybase, HN, SO, PGP."""
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return

    node_id = _entity_key(EntityType.USERNAME.value, username)
    metadata: dict[str, Any] = {"username": username}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id,
         "relationship": "social_lookup", "confidence": 1.0},
    ]

    # ===================================================================
    # 1. Reddit — deep analysis
    # ===================================================================
    try:
        r = httpx.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=_REDDIT_UA, timeout=15, follow_redirects=True,
        )
        if r.status_code == 200:
            rdata = r.json().get("data", {})
            metadata["reddit_name"] = rdata.get("name")
            metadata["reddit_karma"] = rdata.get("total_karma")
            metadata["reddit_created"] = rdata.get("created_utc")
            metadata["reddit_verified"] = rdata.get("verified")
            metadata["reddit_is_employee"] = rdata.get("is_employee", False)
            reddit_bio = (
                rdata.get("subreddit", {}).get("public_description") or ""
            ).strip()
            if reddit_bio:
                metadata["reddit_bio"] = reddit_bio

            comments = _paginate_reddit_listing(username, "comments")
            posts = _paginate_reddit_listing(username, "submitted")

            if comments or posts:
                payload = _build_reddit_analysis_payload(
                    comments, posts, username,
                )

                metadata["reddit_total_comments"] = payload["total_comments"]
                metadata["reddit_total_posts"] = payload["total_posts"]
                metadata["reddit_subreddit_distribution"] = dict(
                    list(payload["subreddit_counts"].items())[:20]
                )
                metadata["reddit_extracted_emails"] = payload["all_emails"]
                metadata["reddit_extracted_urls"] = payload["all_urls"][:50]
                metadata["reddit_frequent_partners"] = dict(
                    list(payload["u_mention_counts"].items())[:15]
                )

                analysis = _analyze_reddit_with_claude(payload, username)
                if analysis:
                    metadata["reddit_inferred_interests"] = analysis.get(
                        "inferred_interests", []
                    )
                    metadata["reddit_inferred_profession"] = analysis.get(
                        "inferred_profession"
                    )
                    metadata["reddit_inferred_location"] = analysis.get(
                        "inferred_location"
                    )
                    metadata["reddit_notable_comments"] = analysis.get(
                        "notable_comments", []
                    )[:5]
                    metadata["reddit_identity_signals"] = analysis.get(
                        "identity_signals", []
                    )[:10]

                for em in payload["all_emails"][:10]:
                    ek = _entity_key(EntityType.EMAIL.value, em)
                    edges_batch.append({
                        "source": node_id, "target": ek,
                        "relationship": "reddit_mentioned_email",
                        "confidence": 0.6,
                    })

                for url in payload["all_urls"][:20]:
                    try:
                        host = urlparse(url).hostname or ""
                        if host and "." in host and len(host) > 4:
                            dk = _entity_key(EntityType.DOMAIN.value, host)
                            edges_batch.append({
                                "source": node_id, "target": dk,
                                "relationship": "reddit_linked_domain",
                                "confidence": 0.4,
                            })
                    except Exception:
                        pass
    except Exception as e:
        _log_service_error(scan_id, node_id, "Reddit", e)

    # ===================================================================
    # 2. Keybase — linked accounts + proof verification
    # ===================================================================
    try:
        r = httpx.get(
            f"https://keybase.io/{username}/lookup.json",
            timeout=15, follow_redirects=True,
        )
        if r.status_code == 200:
            kbdata = r.json()
            them = kbdata.get("them")
            if them:
                them_data = them[0] if isinstance(them, list) else them
                basics = them_data.get("basics", {})
                metadata["keybase_username"] = basics.get("username")
                metadata["keybase_uid"] = basics.get("uid")
                proofs = (
                    them_data.get("proofs_summary", {}).get("all", [])
                )
                linked_accounts: list[dict] = []
                for proof in proofs:
                    proof_type = proof.get("proof_type", "")
                    nametag = proof.get("nametag", "")
                    service_url = proof.get("service_url", "")
                    human_url = proof.get("human_url", service_url)

                    verified = _verify_keybase_proof(
                        human_url or service_url
                    ) if (human_url or service_url) else False

                    linked_accounts.append({
                        "service": proof_type,
                        "username": nametag,
                        "url": service_url,
                        "verified": verified,
                    })

                    if proof_type in (
                        "twitter", "github", "reddit", "hackernews",
                    ) and nametag:
                        uk = _entity_key(
                            EntityType.USERNAME.value, nametag,
                        )
                        edges_batch.append({
                            "source": node_id, "target": uk,
                            "relationship": f"keybase_{proof_type}",
                            "confidence": 0.95 if verified else 0.7,
                        })
                    elif proof_type in (
                        "bitcoin", "zcash", "stellar",
                    ) and nametag:
                        wk = _entity_key(EntityType.WALLET.value, nametag)
                        edges_batch.append({
                            "source": node_id, "target": wk,
                            "relationship": f"keybase_{proof_type}_wallet",
                            "confidence": 0.95 if verified else 0.7,
                        })
                    elif proof_type == "generic_web_site" and service_url:
                        try:
                            domain = urlparse(service_url).hostname or ""
                            if domain and "." in domain:
                                dk = _entity_key(
                                    EntityType.DOMAIN.value, domain,
                                )
                                edges_batch.append({
                                    "source": node_id, "target": dk,
                                    "relationship": "keybase_website",
                                    "confidence": 0.85 if verified else 0.6,
                                })
                        except Exception as parse_err:
                            _log_service_error(
                                scan_id, node_id,
                                "Keybase website parse", parse_err,
                            )

                metadata["keybase_linked_accounts"] = linked_accounts
    except Exception as e:
        _log_service_error(scan_id, node_id, "Keybase", e)

    # ===================================================================
    # 3. Hacker News — profile + full history
    # ===================================================================
    try:
        hn_profile = _fetch_hn_profile(username)
        if hn_profile and hn_profile.get("username"):
            metadata["hn_username"] = hn_profile.get("username")
            metadata["hn_karma"] = hn_profile.get("karma")
            metadata["hn_about"] = (hn_profile.get("about") or "")[:500]
            metadata["hn_created"] = hn_profile.get("created_at")

            hn_items = _paginate_hn_items(username)
            if hn_items:
                hn_data = _process_hn_items(hn_items)
                metadata["hn_story_count"] = hn_data["story_count"]
                metadata["hn_comment_count"] = hn_data["comment_count"]
                metadata["hn_top_domains"] = hn_data["top_domains"]
                metadata["hn_extracted_emails"] = hn_data[
                    "extracted_emails"
                ]
                metadata["hn_extracted_urls"] = hn_data[
                    "extracted_urls"
                ][:20]

                for em in hn_data["extracted_emails"][:5]:
                    ek = _entity_key(EntityType.EMAIL.value, em)
                    edges_batch.append({
                        "source": node_id, "target": ek,
                        "relationship": "hn_mentioned_email",
                        "confidence": 0.6,
                    })

                for domain, count in list(
                    hn_data["top_domains"].items()
                )[:5]:
                    if count >= 2:
                        dk = _entity_key(EntityType.DOMAIN.value, domain)
                        edges_batch.append({
                            "source": node_id, "target": dk,
                            "relationship": "hn_frequently_linked",
                            "confidence": 0.5,
                        })
    except Exception as e:
        _log_service_error(scan_id, node_id, "HackerNews", e)

    # ===================================================================
    # 4. Stack Overflow — profile, tags, cross-site accounts
    # ===================================================================
    try:
        so_user = _search_so_user(username)
        if so_user:
            so_uid = so_user.get("user_id")
            metadata["so_user_id"] = so_uid
            metadata["so_display_name"] = so_user.get("display_name")
            metadata["so_reputation"] = so_user.get("reputation")
            metadata["so_profile_link"] = so_user.get("link")
            metadata["so_question_count"] = so_user.get("question_count")
            metadata["so_answer_count"] = so_user.get("answer_count")

            if so_uid:
                top_tags = _fetch_so_top_tags(so_uid)
                if top_tags:
                    metadata["so_top_tags"] = [
                        {
                            "tag_name": t.get("tag_name"),
                            "question_count": t.get("question_count"),
                            "answer_count": t.get("answer_count"),
                            "question_score": t.get("question_score"),
                            "answer_score": t.get("answer_score"),
                        }
                        for t in top_tags[:15]
                    ]

                associated = _fetch_so_associated(so_uid)
                if associated:
                    metadata["so_associated_sites"] = [
                        {
                            "site_name": a.get("site_name"),
                            "site_url": a.get("site_url"),
                            "reputation": a.get("reputation"),
                            "question_count": a.get("question_count"),
                            "answer_count": a.get("answer_count"),
                        }
                        for a in associated[:20]
                    ]

                    for site_acct in associated:
                        site_url = site_acct.get("site_url", "")
                        if site_url:
                            try:
                                host = urlparse(site_url).hostname or ""
                                if host and "." in host:
                                    dk = _entity_key(
                                        EntityType.DOMAIN.value, host,
                                    )
                                    edges_batch.append({
                                        "source": node_id, "target": dk,
                                        "relationship": "so_network_site",
                                        "confidence": 0.5,
                                    })
                            except Exception:
                                pass
    except Exception as e:
        _log_service_error(scan_id, node_id, "StackOverflow", e)

    # ===================================================================
    # 5. PGP key server (unchanged)
    # ===================================================================
    try:
        search_term = (
            str(entity_value)
            if not isinstance(entity_value, str)
            else entity_value
        ).strip()
        r = httpx.get(
            "https://keys.openpgp.org/vks/v1/search",
            params={"q": search_term},
            timeout=15,
        )
        if r.status_code == 200:
            pgp_data = r.json()
            keys_found = pgp_data.get("keys", [])
            pgp_results = []
            for key in keys_found[:10]:
                for uid in key.get("userids", []):
                    email = (uid.get("email") or "").strip().lower()
                    name = (uid.get("name") or "").strip()
                    if email and "@" in email:
                        pgp_results.append({
                            "email": email,
                            "name": name,
                            "fingerprint": key.get("fingerprint"),
                        })
                        ek = _entity_key(EntityType.EMAIL.value, email)
                        edges_batch.append({
                            "source": node_id, "target": ek,
                            "relationship": "pgp_uid_email",
                            "confidence": 0.9,
                        })
            metadata["pgp_keys"] = pgp_results[:10]
    except Exception as e:
        _log_service_error(scan_id, node_id, "PGP keys.openpgp.org", e)

    # ===================================================================
    # Write node + edges
    # ===================================================================
    node_payload = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)
