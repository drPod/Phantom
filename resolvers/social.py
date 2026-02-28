"""Social resolver: Reddit, Keybase, PGP key servers."""

import logging
import re
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType

logger = logging.getLogger(__name__)

SOURCE = "social_resolver"

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _extract_emails(text: str) -> set[str]:
    return {m.lower() for m in _EMAIL_RE.findall(text)}


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_social(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    q: modal.Queue,
    d: modal.Dict,
) -> None:
    """Resolve a username via Reddit, Keybase, and PGP key servers."""
    if "stop" in d:
        return
    username = (entity_value or "").strip()
    if not username:
        return

    node_id = _entity_key(EntityType.USERNAME.value, username)
    metadata: dict[str, Any] = {"username": username}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "social_lookup", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []

    # 1. Reddit — user about + recent posts
    try:
        r = httpx.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={"User-Agent": "osint-recon/1.0"},
            timeout=15,
            follow_redirects=True,
        )
        if r.status_code == 200:
            rdata = r.json().get("data", {})
            metadata["reddit_name"] = rdata.get("name")
            metadata["reddit_karma"] = rdata.get("total_karma")
            metadata["reddit_created"] = rdata.get("created_utc")
            metadata["reddit_verified"] = rdata.get("verified")
            metadata["reddit_is_employee"] = rdata.get("is_employee", False)
    except Exception as e:
        logger.warning("Reddit about failed for %s: %s", username, e)

    # Recent posts — scan for mentioned emails/domains
    try:
        r = httpx.get(
            f"https://www.reddit.com/user/{username}/submitted.json",
            headers={"User-Agent": "osint-recon/1.0"},
            params={"limit": "25"},
            timeout=15,
            follow_redirects=True,
        )
        if r.status_code == 200:
            posts = r.json().get("data", {}).get("children", [])
            mentioned_emails: set[str] = set()
            mentioned_usernames: set[str] = set()
            for post in posts:
                pdata = post.get("data", {})
                text = " ".join(filter(None, [
                    pdata.get("title", ""),
                    pdata.get("selftext", ""),
                    pdata.get("url", ""),
                ]))
                for em in _extract_emails(text):
                    mentioned_emails.add(em)
                # u/mentions in post text
                for um in re.findall(r"u/([A-Za-z0-9_\-]{3,20})", text):
                    if um.lower() != username.lower():
                        mentioned_usernames.add(um)
            metadata["reddit_mentioned_emails"] = list(mentioned_emails)[:10]
            metadata["reddit_mentioned_users"] = list(mentioned_usernames)[:10]
            for em in list(mentioned_emails)[:5]:
                ek = _entity_key(EntityType.EMAIL.value, em)
                to_push.append({
                    "type": EntityType.EMAIL.value,
                    "value": em,
                    "source": SOURCE,
                    "confidence": 0.6,
                    "depth": depth + 1,
                    "parent_key": node_id,
                })
                edges_batch.append({
                    "source": node_id,
                    "target": ek,
                    "relationship": "reddit_mentioned_email",
                    "confidence": 0.6,
                })
    except Exception as e:
        logger.warning("Reddit posts failed for %s: %s", username, e)

    # 2. Keybase — linked accounts (Twitter, GitHub, Reddit, Bitcoin, etc.)
    try:
        r = httpx.get(
            f"https://keybase.io/{username}/lookup.json",
            timeout=15,
            follow_redirects=True,
        )
        if r.status_code == 200:
            kbdata = r.json()
            them = kbdata.get("them")
            if them:
                them_data = them[0] if isinstance(them, list) else them
                basics = them_data.get("basics", {})
                metadata["keybase_username"] = basics.get("username")
                metadata["keybase_uid"] = basics.get("uid")
                proofs = them_data.get("proofs_summary", {}).get("all", [])
                linked_accounts: list[dict] = []
                for proof in proofs:
                    proof_type = proof.get("proof_type", "")
                    nametag = proof.get("nametag", "")
                    service_url = proof.get("service_url", "")
                    linked_accounts.append({
                        "service": proof_type,
                        "username": nametag,
                        "url": service_url,
                    })
                    # Push known platforms as username entities
                    if proof_type in ("twitter", "github", "reddit", "hackernews") and nametag:
                        uk = _entity_key(EntityType.USERNAME.value, nametag)
                        to_push.append({
                            "type": EntityType.USERNAME.value,
                            "value": nametag,
                            "source": SOURCE,
                            "confidence": 0.95,
                            "depth": depth + 1,
                            "parent_key": node_id,
                        })
                        edges_batch.append({
                            "source": node_id,
                            "target": uk,
                            "relationship": f"keybase_{proof_type}",
                            "confidence": 0.95,
                        })
                    # Bitcoin wallet address
                    elif proof_type in ("bitcoin", "zcash", "stellar") and nametag:
                        wk = _entity_key(EntityType.WALLET.value, nametag)
                        to_push.append({
                            "type": EntityType.WALLET.value,
                            "value": nametag,
                            "source": SOURCE,
                            "confidence": 0.95,
                            "depth": depth + 1,
                            "parent_key": node_id,
                        })
                        edges_batch.append({
                            "source": node_id,
                            "target": wk,
                            "relationship": f"keybase_{proof_type}_wallet",
                            "confidence": 0.95,
                        })
                    # Website domain
                    elif proof_type == "generic_web_site" and service_url:
                        try:
                            from urllib.parse import urlparse
                            domain = urlparse(service_url).hostname or ""
                            if domain and "." in domain:
                                dk = _entity_key(EntityType.DOMAIN.value, domain)
                                to_push.append({
                                    "type": EntityType.DOMAIN.value,
                                    "value": domain,
                                    "source": SOURCE,
                                    "confidence": 0.85,
                                    "depth": depth + 1,
                                    "parent_key": node_id,
                                })
                                edges_batch.append({
                                    "source": node_id,
                                    "target": dk,
                                    "relationship": "keybase_website",
                                    "confidence": 0.85,
                                })
                        except Exception:
                            pass

                metadata["keybase_linked_accounts"] = linked_accounts
    except Exception as e:
        logger.warning("Keybase lookup failed for %s: %s", username, e)

    # 3. PGP key server — search by username (treat as name/uid query)
    # Only useful if entity looks like an email; for usernames we query anyway.
    try:
        search_term = entity_value.strip()
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
                        pgp_results.append({"email": email, "name": name, "fingerprint": key.get("fingerprint")})
                        ek = _entity_key(EntityType.EMAIL.value, email)
                        to_push.append({
                            "type": EntityType.EMAIL.value,
                            "value": email,
                            "source": SOURCE,
                            "confidence": 0.9,
                            "depth": depth + 1,
                            "parent_key": node_id,
                        })
                        edges_batch.append({
                            "source": node_id,
                            "target": ek,
                            "relationship": "pgp_uid_email",
                            "confidence": 0.9,
                        })
            metadata["pgp_keys"] = pgp_results[:10]
    except Exception as e:
        logger.warning("PGP lookup failed for %s: %s", username, e)

    # Write node
    d[f"{NODE_PREFIX}{node_id}"] = {
        "id": node_id,
        "type": EntityType.USERNAME.value,
        "value": username,
        "metadata": metadata,
        "depth": depth,
    }

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch

    for item in to_push:
        q.put(item)
