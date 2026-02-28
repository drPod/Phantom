"""Domain resolver: crt.sh, WhoisXML, DNS (dnspython), SecurityTrails."""

import logging
import os
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
import modal

from app import app, image, osint_secret
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "domain_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = value.strip().lower()
    return f"{etype}:{v}"


def _backoff(attempt: int) -> None:
    time.sleep(min(2**attempt, 60))


def _clean_domain(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if raw.startswith("*."):
        raw = raw[2:]
    try:
        if not raw.startswith("http"):
            parsed = urlparse("https://" + raw)
        else:
            parsed = urlparse(raw)
        return parsed.hostname or raw
    except Exception:
        return raw


@app.function(image=image, secrets=[osint_secret])
@modal.concurrent(max_inputs=10)
def resolve_domain(
    entity_value: str,
    entity_type: str,
    depth: int,
    source_entity_key: str,
    scan_id: str = "",
) -> None:
    """Resolve a domain via crt.sh, WhoisXML, DNS lookups, and SecurityTrails."""
    if not scan_id:
        return
    q = modal.Queue.from_name(f"osint-q-{scan_id}", create_if_missing=True)
    d = modal.Dict.from_name(f"osint-d-{scan_id}", create_if_missing=True)
    if "stop" in d:
        return
    domain = (entity_value or "").strip().lower()
    if not domain or "." not in domain:
        return

    node_id = _entity_key(EntityType.DOMAIN.value, domain)
    metadata: dict[str, Any] = {"domain": domain}
    edges_batch: list[dict[str, Any]] = [
        {"source": source_entity_key, "target": node_id, "relationship": "resolved_domain", "confidence": 1.0}
    ]
    to_push: list[dict[str, Any]] = []

    discovered_emails: set[str] = set()
    discovered_domains: set[str] = set()

    # 1. crt.sh — certificate transparency (subdomains + org names)
    try:
        r = httpx.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=30,
            headers={"User-Agent": "osint-recon/1.0"},
        )
        if r.status_code == 200:
            certs = r.json()
            subdomain_set: set[str] = set()
            org_set: set[str] = set()
            for cert in certs:
                name_value = cert.get("name_value", "")
                issuer_org = (cert.get("issuer_o") or "").strip()
                if issuer_org:
                    org_set.add(issuer_org)
                for name in name_value.split("\n"):
                    cleaned = _clean_domain(name)
                    if cleaned and cleaned.endswith(domain) and cleaned != domain:
                        subdomain_set.add(cleaned)
                    elif cleaned and "." in cleaned and domain in cleaned:
                        subdomain_set.add(cleaned)
            metadata["crt_sh_subdomains"] = sorted(subdomain_set)[:50]
            metadata["crt_sh_orgs"] = sorted(org_set)[:20]
            for sub in list(subdomain_set)[:30]:
                discovered_domains.add(sub)
    except Exception as e:
        logger.warning("crt.sh failed for %s: %s", domain, e)

    # 2. DNS lookups (A, MX, TXT) via dnspython
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10

        for rtype in ("A", "MX", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                if rtype == "A":
                    metadata["dns_a"] = [str(r) for r in answers]
                elif rtype == "MX":
                    mx_hosts = []
                    for rdata in answers:
                        mx_host = str(rdata.exchange).rstrip(".")
                        mx_hosts.append(mx_host)
                        if mx_host and "." in mx_host:
                            discovered_domains.add(mx_host)
                    metadata["dns_mx"] = mx_hosts
                elif rtype == "TXT":
                    txt_records = [b.decode("utf-8", errors="replace") for rdata in answers for b in rdata.strings]
                    metadata["dns_txt"] = txt_records
            except Exception:
                pass
    except ImportError:
        logger.warning("dnspython not available")
    except Exception as e:
        logger.warning("DNS lookup failed for %s: %s", domain, e)

    # 3. WhoisXML API
    whoisxml_key = os.environ.get("WHOISXML_KEY", "")
    if whoisxml_key:
        try:
            r = httpx.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "apiKey": whoisxml_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
                timeout=20,
            )
            if r.status_code == 200:
                wdata = r.json().get("WhoisRecord", {})
                registrant = wdata.get("registrant", {})
                admin = wdata.get("administrativeContact", {})
                metadata["whois_registrant_org"] = registrant.get("organization")
                metadata["whois_registrant_name"] = registrant.get("name")
                metadata["whois_registrant_country"] = registrant.get("country")
                metadata["whois_created_date"] = wdata.get("createdDate")
                metadata["whois_updated_date"] = wdata.get("updatedDate")
                metadata["whois_expires_date"] = wdata.get("expiresDate")
                metadata["whois_registrar"] = wdata.get("registrarName")
                for contact in (registrant, admin):
                    email = (contact.get("email") or "").strip().lower()
                    if email and "@" in email and "registrar" not in email:
                        discovered_emails.add(email)
                    phone = (contact.get("telephone") or "").strip()
                    if phone:
                        metadata.setdefault("whois_phones", []).append(phone)
        except Exception as e:
            logger.warning("WhoisXML failed for %s: %s", domain, e)

    # 4. SecurityTrails — historical DNS + subdomains
    sectrails_key = os.environ.get("SECURITYTRAILS_KEY", "")
    if sectrails_key:
        try:
            r = httpx.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"APIKEY": sectrails_key},
                timeout=20,
            )
            if r.status_code == 200:
                st_subs = r.json().get("subdomains", [])
                metadata["securitytrails_subdomains"] = st_subs[:50]
                for sub in st_subs[:30]:
                    fqdn = f"{sub}.{domain}"
                    discovered_domains.add(fqdn)
        except Exception as e:
            logger.warning("SecurityTrails subdomains failed for %s: %s", domain, e)

        try:
            r = httpx.get(
                f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                headers={"APIKEY": sectrails_key},
                timeout=20,
            )
            if r.status_code == 200:
                records = r.json().get("records", [])
                historical_ips = []
                for rec in records[:20]:
                    for v in rec.get("values", []):
                        ip = v.get("ip")
                        if ip:
                            historical_ips.append(ip)
                metadata["securitytrails_historical_ips"] = historical_ips
        except Exception as e:
            logger.warning("SecurityTrails history failed for %s: %s", domain, e)

    # Push discovered emails
    for email in discovered_emails:
        ek = _entity_key(EntityType.EMAIL.value, email)
        to_push.append({
            "type": EntityType.EMAIL.value,
            "value": email,
            "source": SOURCE,
            "confidence": 0.85,
            "depth": depth + 1,
            "parent_key": node_id,
        })
        edges_batch.append({
            "source": node_id,
            "target": ek,
            "relationship": "whois_contact_email",
            "confidence": 0.85,
        })

    # Push discovered subdomains/related domains (limit to avoid explosion)
    for sub_domain in list(discovered_domains)[:20]:
        sd = _clean_domain(sub_domain)
        if not sd or sd == domain:
            continue
        dk = _entity_key(EntityType.DOMAIN.value, sd)
        to_push.append({
            "type": EntityType.DOMAIN.value,
            "value": sd,
            "source": SOURCE,
            "confidence": 0.75,
            "depth": depth + 1,
            "parent_key": node_id,
        })
        edges_batch.append({
            "source": node_id,
            "target": dk,
            "relationship": "subdomain",
            "confidence": 0.75,
        })

    # Write node
    node_payload = {
        "id": node_id,
        "type": EntityType.DOMAIN.value,
        "value": domain,
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
