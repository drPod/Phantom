"""Email resolver: Hunter.io, EmailRep.io, Gravatar, HIBP, Kickbox."""

import hashlib
import logging
import os
import time
import uuid
from typing import Any

import httpx
import modal
from emailrep import EmailRep

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
    scan_id: str = "",
) -> None:
    """Resolve an email via Hunter.io, EmailRep.io, Gravatar, HIBP, and Kickbox."""
    if not scan_id:
        return
    q = modal.Queue.from_name(f"osint-q-{scan_id}", create_if_missing=True)
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
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

    # 2. WhoisXML Email Verification API — SMTP/DNS/disposable/free/catch-all checks
    whoisxml_key = os.environ.get("WHOISXML_KEY", "")
    if whoisxml_key:
        try:
            r = httpx.get(
                "https://emailverification.whoisxmlapi.com/api/v2",
                params={
                    "apiKey": whoisxml_key,
                    "emailAddress": email,
                    "outputFormat": "JSON",
                    "validateDNS": 1,
                    "validateSMTP": 1,
                    "checkCatchAll": 1,
                    "checkFree": 1,
                    "checkDisposable": 1,
                },
                timeout=30,
            )
            if r.status_code == 200:
                evdata = r.json()
                metadata["whoisxml_email_format_valid"] = evdata.get("formatCheck") == "true"
                metadata["whoisxml_email_smtp_valid"] = evdata.get("smtpCheck") == "true"
                metadata["whoisxml_email_dns_valid"] = evdata.get("dnsCheck") == "true"
                metadata["whoisxml_email_free_provider"] = evdata.get("freeCheck") == "true"
                metadata["whoisxml_email_disposable"] = evdata.get("disposableCheck") == "true"
                metadata["whoisxml_email_catch_all"] = evdata.get("catchAllCheck") == "true"
                mx_records = evdata.get("mxRecords", [])
                if mx_records:
                    metadata["whoisxml_email_mx_records"] = mx_records
        except Exception as e:
            logger.warning("WhoisXML Email Verification failed for %s: %s", email, e)

    # 3. Gravatar — hash email, fetch profile JSON
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

    # 4. Hunter.io — email verifier + person enrichment
    hunter_key = os.environ.get("HUNTER_API_KEY", "")
    if hunter_key:
        hunter_headers = {"X-API-KEY": hunter_key}

        # 3a. Email Verifier
        for attempt in range(3):
            try:
                r = httpx.get(
                    "https://api.hunter.io/v2/email-verifier",
                    params={"email": email},
                    headers=hunter_headers,
                    timeout=15,
                )
                if r.status_code == 200:
                    hdata = r.json().get("data", {})
                    metadata["hunter_status"] = hdata.get("status")
                    metadata["hunter_score"] = hdata.get("score")
                    metadata["hunter_disposable"] = hdata.get("disposable")
                    metadata["hunter_webmail"] = hdata.get("webmail")
                    metadata["hunter_smtp_check"] = hdata.get("smtp_check")
                    metadata["hunter_mx_records"] = hdata.get("mx_records")
                    metadata["hunter_smtp_server"] = hdata.get("smtp_server")
                    sources = hdata.get("sources", [])
                    if sources:
                        metadata["hunter_sources"] = [
                            {"uri": s.get("uri"), "extracted_on": s.get("extracted_on")}
                            for s in sources[:10]
                        ]
                    hdomain = (hdata.get("domain") or "").strip()
                    if hdomain and "." in hdomain:
                        dk = _entity_key(EntityType.DOMAIN.value, hdomain)
                        to_push.append({
                            "type": EntityType.DOMAIN.value,
                            "value": hdomain,
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
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 0) or 0)
                    _backoff(attempt, retry_after or 60)
                    continue
                break
            except Exception as e:
                logger.warning("Hunter.io verifier failed for %s (attempt %s): %s", email, attempt + 1, e)
                _backoff(attempt)

        # 3b. Person Enrichment — name, location, social handles
        for attempt in range(3):
            try:
                r = httpx.get(
                    "https://api.hunter.io/v2/people/find",
                    params={"email": email},
                    headers=hunter_headers,
                    timeout=15,
                )
                if r.status_code == 200:
                    pdata = r.json().get("data", {})
                    metadata["hunter_full_name"] = pdata.get("full_name")
                    metadata["hunter_position"] = pdata.get("position")
                    metadata["hunter_headline"] = pdata.get("headline")
                    metadata["hunter_city"] = pdata.get("city")
                    metadata["hunter_country"] = pdata.get("country")
                    metadata["hunter_company"] = pdata.get("company")
                    metadata["hunter_linkedin"] = pdata.get("linkedin")
                    metadata["hunter_twitter"] = pdata.get("twitter")
                    metadata["hunter_github"] = pdata.get("github")
                    for social_key in ("twitter", "github"):
                        handle = (pdata.get(social_key) or "").strip()
                        if handle:
                            uk = _entity_key(EntityType.USERNAME.value, handle)
                            to_push.append({
                                "type": EntityType.USERNAME.value,
                                "value": handle,
                                "source": SOURCE,
                                "confidence": 0.85,
                                "depth": depth + 1,
                                "parent_key": node_id,
                            })
                            edges_batch.append({
                                "source": node_id,
                                "target": uk,
                                "relationship": f"hunter_{social_key}",
                                "confidence": 0.85,
                            })
                elif r.status_code == 404:
                    pass  # no person record found
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 0) or 0)
                    _backoff(attempt, retry_after or 60)
                    continue
                break
            except Exception as e:
                logger.warning("Hunter.io person enrichment failed for %s (attempt %s): %s", email, attempt + 1, e)
                _backoff(attempt)

    # 5. EmailRep.io — reputation + breach presence (official library; works without API key)
    emailrep_key = os.environ.get("EMAILREP_KEY", "")
    try:
        client = EmailRep(key=emailrep_key or None)
        erdata = client.query(email)
        if isinstance(erdata, dict) and "reputation" in erdata:
            metadata["emailrep_reputation"] = erdata.get("reputation")
            metadata["emailrep_suspicious"] = erdata.get("suspicious")
            metadata["emailrep_references"] = erdata.get("references")
            attrs = erdata.get("details") or {}
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
        elif isinstance(erdata, dict) and ("detail" in erdata or "error" in erdata):
            logger.warning("EmailRep.io returned error for %s: %s", email, erdata.get("detail", erdata.get("error")))
    except Exception as e:
        logger.warning("EmailRep.io check failed for %s: %s", email, e)

    # 6. HIBP — breach lookup, paste lookup, and stealer logs (v3)
    hibp_key = os.environ.get("HIBP_KEY", "")
    if hibp_key:
        _hibp_headers = {
            "hibp-api-key": hibp_key,
            "User-Agent": "osint-recon/1.0",
        }

        # 6a. Breached account
        for attempt in range(3):
            try:
                r = httpx.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers=_hibp_headers,
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
                            "is_verified": b.get("IsVerified", True),
                            "is_sensitive": b.get("IsSensitive", False),
                        }
                        for b in breaches
                    ]
                elif r.status_code == 404:
                    metadata["hibp_breach_count"] = 0
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("retry-after", 60) or 60)
                    _backoff(attempt, retry_after)
                    continue
                break
            except Exception as e:
                logger.warning("HIBP breaches attempt %s failed for %s: %s", attempt + 1, email, e)
                _backoff(attempt)

        # 6b. Pastes for account
        for attempt in range(3):
            try:
                r = httpx.get(
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                    headers=_hibp_headers,
                    timeout=15,
                )
                if r.status_code == 200:
                    pastes = r.json()
                    metadata["hibp_paste_count"] = len(pastes)
                    metadata["hibp_paste_detail"] = [
                        {
                            "source": p.get("Source"),
                            "id": p.get("Id"),
                            "title": p.get("Title"),
                            "date": p.get("Date"),
                            "email_count": p.get("EmailCount"),
                        }
                        for p in pastes[:20]
                    ]
                elif r.status_code == 404:
                    metadata["hibp_paste_count"] = 0
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("retry-after", 60) or 60)
                    _backoff(attempt, retry_after)
                    continue
                break
            except Exception as e:
                logger.warning("HIBP pastes attempt %s failed for %s: %s", attempt + 1, email, e)
                _backoff(attempt)

        # 6c. Stealer logs by email (requires Pwned 5+ subscription; silently skipped on 401/403)
        for attempt in range(3):
            try:
                r = httpx.get(
                    f"https://haveibeenpwned.com/api/v3/stealerlogsbyemail/{email}",
                    headers=_hibp_headers,
                    timeout=15,
                )
                if r.status_code == 200:
                    stealer_domains = r.json()
                    metadata["hibp_stealer_log_domains"] = stealer_domains[:50]
                elif r.status_code == 404:
                    metadata["hibp_stealer_log_domains"] = []
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("retry-after", 60) or 60)
                    _backoff(attempt, retry_after)
                    continue
                break
            except Exception as e:
                logger.warning("HIBP stealer logs attempt %s failed for %s: %s", attempt + 1, email, e)
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
