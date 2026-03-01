"""Phone resolver: Numverify and Veriphone APIs for carrier, line type, and location."""

import logging
import os
import re
import time
import uuid
from typing import Any

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "phone_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
    return f"{etype}:{v}"


def _normalize_phone(raw: str) -> str:
    """Keep leading + and digits only; return empty string if fewer than 7 digits."""
    raw = raw.strip()
    has_plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 7:
        return ""
    return ("+" if has_plus else "") + digits


def _backoff(attempt: int, retry_after: int | None = None) -> None:
    if retry_after and retry_after > 0:
        time.sleep(min(retry_after, 60))
    else:
        time.sleep(min(2**attempt, 60))


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_phone(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Resolve a phone number via Numverify and Veriphone APIs."""
    if not scan_id:
        return
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return

    phone = _normalize_phone(entity_value or "")
    if not phone:
        return

    node_id = _entity_key(EntityType.PHONE.value, phone)
    metadata: dict[str, Any] = {"phone": phone}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "resolved_phone", "confidence": 1.0}
    ]

    # 1. Numverify (100 req/month, HTTP only on free tier)
    numverify_key = os.environ.get("NUMVERIFY_KEY", "")
    if numverify_key:
        for attempt in range(3):
            try:
                r = httpx.get(
                    "http://apilayer.net/api/validate",
                    params={"access_key": numverify_key, "number": phone},
                    timeout=15,
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get("error"):
                        err = data["error"]
                        logger.warning("Numverify error for %s: %s", phone, err)
                        log_scan_event(
                            scan_id,
                            "resolver_failed",
                            resolver="resolve_phone",
                            entity_key=node_id,
                            error=str(err),
                            service="Numverify",
                            response_preview=str(data)[:500],
                        )
                    else:
                        metadata["numverify_valid"] = data.get("valid")
                        metadata["numverify_local_format"] = data.get("local_format")
                        metadata["numverify_international_format"] = data.get("international_format")
                        metadata["numverify_country_prefix"] = data.get("country_prefix")
                        metadata["numverify_country_code"] = data.get("country_code")
                        metadata["numverify_country_name"] = data.get("country_name")
                        metadata["numverify_location"] = data.get("location")
                        metadata["numverify_carrier"] = data.get("carrier")
                        metadata["numverify_line_type"] = data.get("line_type")
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 0) or 0)
                    _backoff(attempt, retry_after or 60)
                    continue
                else:
                    response_preview = (r.text or "")[:500]
                    logger.warning("Numverify returned status %s for %s: %s", r.status_code, phone, response_preview)
                    log_scan_event(
                        scan_id,
                        "resolver_failed",
                        resolver="resolve_phone",
                        entity_key=node_id,
                        error=f"Numverify status {r.status_code}",
                        service="Numverify",
                        response_preview=response_preview,
                    )
                break
            except Exception as e:
                response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
                logger.warning("Numverify failed for %s (attempt %s): %s", phone, attempt + 1, e)
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_phone",
                    entity_key=node_id,
                    error=str(e),
                    service="Numverify",
                    response_preview=response_preview,
                )
                _backoff(attempt)

    # 2. Veriphone (1,000 req/month, HTTPS, richest free data)
    veriphone_key = os.environ.get("VERIPHONE_KEY", "")
    if veriphone_key:
        for attempt in range(3):
            try:
                r = httpx.get(
                    "https://api.veriphone.io/v2/verify",
                    params={"phone": phone, "key": veriphone_key},
                    timeout=15,
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        metadata["veriphone_valid"] = data.get("phone_valid")
                        metadata["veriphone_phone_type"] = data.get("phone_type")
                        metadata["veriphone_phone_region"] = data.get("phone_region")
                        metadata["veriphone_country"] = data.get("country")
                        metadata["veriphone_country_code"] = data.get("country_code")
                        metadata["veriphone_country_prefix"] = data.get("country_prefix")
                        metadata["veriphone_carrier"] = data.get("carrier")
                        metadata["veriphone_international_number"] = data.get("international_number")
                        metadata["veriphone_local_number"] = data.get("local_number")
                        metadata["veriphone_e164"] = data.get("e164")
                    else:
                        logger.warning("Veriphone non-success status for %s: %s", phone, data.get("status"))
                        log_scan_event(
                            scan_id,
                            "resolver_failed",
                            resolver="resolve_phone",
                            entity_key=node_id,
                            error=f"Veriphone status: {data.get('status')}",
                            service="Veriphone",
                            response_preview=str(data)[:500],
                        )
                elif r.status_code == 429:
                    retry_after = int(r.headers.get("Retry-After", 0) or 0)
                    _backoff(attempt, retry_after or 60)
                    continue
                else:
                    response_preview = (r.text or "")[:500]
                    logger.warning("Veriphone returned status %s for %s: %s", r.status_code, phone, response_preview)
                    log_scan_event(
                        scan_id,
                        "resolver_failed",
                        resolver="resolve_phone",
                        entity_key=node_id,
                        error=f"Veriphone status {r.status_code}",
                        service="Veriphone",
                        response_preview=response_preview,
                    )
                break
            except Exception as e:
                response_preview = (getattr(getattr(e, "response", None), "text", None) or "")[:500]
                logger.warning("Veriphone failed for %s (attempt %s): %s", phone, attempt + 1, e)
                log_scan_event(
                    scan_id,
                    "resolver_failed",
                    resolver="resolve_phone",
                    entity_key=node_id,
                    error=str(e),
                    service="Veriphone",
                    response_preview=response_preview,
                )
                _backoff(attempt)

    # Write node
    node_payload = {
        "id": node_id,
        "type": EntityType.PHONE.value,
        "value": phone,
        "metadata": metadata,
        "depth": depth,
    }
    d[f"{NODE_PREFIX}{node_id}"] = node_payload
    write_stream_event(scan_id, "node", node_payload)

    d[f"{EDGES_BATCH_PREFIX}{uuid.uuid4().hex}"] = edges_batch
    for edge in edges_batch:
        write_stream_event(scan_id, "edge", edge)
