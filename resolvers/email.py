"""Email resolver: Hunter.io, EmailRep.io, Gravatar, HIBP, Kickbox."""

import hashlib
import logging
import os
import time
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "email_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int, retry_after: int | None = None) -> None:
    if retry_after and retry_after > 0:
        time.sleep(min(retry_after, 60))
    else:
        time.sleep(min(2**attempt, 60))


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_email(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    q: modal.Queue,
    d: modal.Dict,
    scan_id: str = "",
) -> None:
    """Resolve an email via Hunter.io, EmailRep.io, Gravatar, HIBP, and Kickbox."""
    if "stop" in d:
        return
    email = (entity_value or "").strip().lower()
    if not email or "@" not in email:
        return

    node_id = _entity_key(EntityType.EMAIL.value, email)
    metadata: dict[str, Any] = {"email": email}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "resolved_email", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []

    # 1. Kickbox disposable check (free, no key)
    try:
        r = httpx.get(
            f"https://open.kickbox.com/v1/disposable/{email}",
            timeout=10,
        )
        if r.status_code == 200:
            metadata["disposable"] = r.json().get("disposable", False)
    except Exception as e:
        logger.warning("Kickbox check failed for %s: %s", email, e)

    # 2. Gravatar — hash email, fetch profile JSON
    try:
        email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        r = httpx.get(
            f"https://www.gravatar.com/{email_hash}.json",
            timeout=10,
            follow_redirects=True,
        )
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            metadata["gravatar_display_name"] = entry.get("displayName")
            metadata["gravatar_username"] = entry.get("preferredUsername")
            metadata["gravatar_profile_url"] = f"https://www.gravatar.com/{email_hash}"
            grav_username = (entry.get("preferredUsername") or "").strip()
            if grav_username:
                uk = _entity_key(EntityType.USERNAME.value, grav_username)
                to_push.append({
                    "type": EntityType.USERNAME.value,
                    "value": grav_username,
                    "source": SOURCE,
                    "confidence": 0.8,
                    "depth": depth + 1,
                    "parent_key": node_id,
                })
                edges_batch.append({
                    "source": node_id,
                    "target": uk,
                    "relationship": "gravatar_username",
                    "confidence": 0.8,
                })
    except Exception as e:
        logger.warning("Gravatar check failed for %s: %s", email, e)

    # 3. Hunter.io email verifier
    hunter_key = os.environ.get("HUNTER_API_KEY", "")
    if hunter_key:
        try:
            r = httpx.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": hunter_key},
                timeout=15,
            )
            if r.status_code == 200:
                hdata = r.json().get("data", {})
                metadata["hunter_status"] = hdata.get("status")
                metadata["hunter_score"] = hdata.get("score")
                metadata["hunter_disposable"] = hdata.get("disposable")
                metadata["hunter_webmail"] = hdata.get("webmail")
                domain = (hdata.get("domain") or "").strip()
                if domain and "." in domain:
                    dk = _entity_key(EntityType.DOMAIN.value, domain)
                    to_push.append({
                        "type": EntityType.DOMAIN.value,
                        "value": domain,
                        "source": SOURCE,
                        "confidence": 0.9,
                        "depth": depth + 1,
                        "parent_key": node_id,
                    })
                    edges_batch.append({
                        "source": node_id,
                        "target": dk,
                        "relationship": "email_domain",
                        "confidence": 0.9,
                    })
        except Exception as e:
            logger.warning("Hunter.io check failed for %s: %s", email, e)

    # 4. EmailRep.io — reputation + breach presence
    emailrep_key = os.environ.get("EMAILREP_KEY", "")
    try:
        headers: dict[str, str] = {"User-Agent": "osint-recon/1.0"}
        if emailrep_key:
            headers["Key"] = emailrep_key
        r = httpx.get(f"https://emailrep.io/{email}", headers=headers, timeout=15)
        if r.status_code == 200:
            erdata = r.json()
            metadata["emailrep_reputation"] = erdata.get("reputation")
            metadata["emailrep_suspicious"] = erdata.get("suspicious")
            metadata["emailrep_references"] = erdata.get("references")
            attrs = erdata.get("details", {})
            profiles = attrs.get("profiles", [])
            metadata["emailrep_profiles"] = profiles
            metadata["emailrep_malicious_activity"] = attrs.get("malicious_activity", False)
            metadata["emailrep_credentials_leaked"] = attrs.get("credentials_leaked", False)
            for profile in profiles:
                uk = _entity_key(EntityType.USERNAME.value, profile)
                to_push.append({
                    "type": EntityType.USERNAME.value,
                    "value": profile,
                    "source": SOURCE,
                    "confidence": 0.7,
                    "depth": depth + 1,
                    "parent_key": node_id,
                })
                edges_batch.append({
                    "source": node_id,
                    "target": uk,
                    "relationship": "emailrep_profile",
                    "confidence": 0.7,
                })
    except Exception as e:
        logger.warning("EmailRep.io check failed for %s: %s", email, e)

    # 5. HIBP — breach lookup
    hibp_key = os.environ.get("HIBP_KEY", "")
    if hibp_key:
        for attempt in range(3):
            try:
                r = httpx.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": hibp_key,
                        "User-Agent": "osint-recon/1.0",
                    },
                    params={"truncateResponse": "false"},
                    timeout=15,
                )
                if r.status_code == 200:
                    breaches = r.json()
                    metadata["hibp_breach_count"] = len(breaches)
                    metadata["hibp_breach_detail"] = [
                        {
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                        }
                        for b in breaches
                    ]
                elif r.status_code == 404:
                    metadata["hibp_breach_count"] = 0
                elif r.status_code == 429:
                    _backoff(attempt, 60)
                    continue
                break
            except Exception as e:
                logger.warning("HIBP attempt %s failed for %s: %s", attempt + 1, email, e)
                _backoff(attempt)

    # Write node
    node_payload = {
        "id": node_id,
        "type": EntityType.EMAIL.value,
        "value": email,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)

    for item in to_push:
        q.put(item)
