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
from resolvers._http import httpx_request
from graph import EDGES_BATCH_PREFIX, NODE_PREFIX
from models import EntityType
from scan_log import log_scan_event
from stream import write_stream_event

logger = logging.getLogger(__name__)

SOURCE = "domain_resolver"


def _entity_key(etype: str, value: str) -> str:
    v = (str(value) if not isinstance(value, str) else value).strip().lower()
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
    except Exception as e:
        logger.debug("_clean_domain failed for %s: %s", raw[:50] if raw else "", e)
        return raw


def _response_preview(r: Any, max_len: int = 500) -> str:
    """Return first max_len chars of response text for logging."""
    try:
        return (getattr(r, "text", None) or "")[:max_len]
    except Exception:
        return ""


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
        r = httpx_request(
            "GET",
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
        else:
            response_preview = _response_preview(r)
            logger.warning("crt.sh returned status %s for %s: %s", r.status_code, domain, response_preview)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=f"crt.sh status {r.status_code}",
                service="crt.sh",
                response_preview=response_preview,
            )
    except Exception as e:
        response_preview = _response_preview(getattr(e, "response", None))
        logger.warning("crt.sh failed for %s: %s", domain, e)
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="resolve_domain",
            entity_key=node_id,
            error=str(e),
            service="crt.sh",
            response_preview=response_preview,
        )

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
            except Exception as e:
                logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)
    except ImportError:
        logger.warning("dnspython not available (service=DNS)")
    except Exception as e:
        logger.warning("DNS lookup failed for %s: %s", domain, e)
        log_scan_event(
            scan_id,
            "resolver_failed",
            resolver="resolve_domain",
            entity_key=node_id,
            error=str(e),
            service="DNS",
        )

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
                    "ip": 1,              # include associated IPs
                    "ignoreRawTexts": 1,  # omit rawText fields for cleaner output
                },
                timeout=60,
            )
            if r.status_code == 200:
                wdata = r.json().get("WhoisRecord", {})

                # Surface dataError for privacy-redacted or missing records
                data_error = wdata.get("dataError", "")
                if data_error:
                    metadata["whois_data_error"] = data_error

                registrant = wdata.get("registrant", {})
                admin = wdata.get("administrativeContact", {})
                tech = wdata.get("technicalContact", {})

                metadata["whois_registrant_org"] = registrant.get("organization")
                metadata["whois_registrant_name"] = registrant.get("name")
                metadata["whois_registrant_country"] = registrant.get("country")
                metadata["whois_registrant_country_code"] = registrant.get("countryCode")
                metadata["whois_registrant_city"] = registrant.get("city")
                metadata["whois_registrant_state"] = registrant.get("state")
                metadata["whois_created_date"] = wdata.get("createdDate")
                metadata["whois_updated_date"] = wdata.get("updatedDate")
                metadata["whois_expires_date"] = wdata.get("expiresDate")
                metadata["whois_estimated_age_days"] = wdata.get("estimatedDomainAge")
                metadata["whois_registrar"] = wdata.get("registrarName")
                metadata["whois_registrar_iana_id"] = wdata.get("registrarIANAID")

                # Name servers
                ns_obj = wdata.get("nameServers", {})
                if isinstance(ns_obj, dict):
                    ns_hosts = ns_obj.get("hostNames", [])
                    if ns_hosts:
                        metadata["whois_nameservers"] = ns_hosts
                        for ns in ns_hosts:
                            if ns and "." in ns:
                                discovered_domains.add(ns.lower())

                # Associated IPs (returned when ip=1)
                raw_ips = wdata.get("ips", [])
                if raw_ips:
                    metadata["whois_ips"] = raw_ips if isinstance(raw_ips, list) else [raw_ips]

                # Harvest emails + phones from registrant, admin, and technical contacts
                for contact in (registrant, admin, tech):
                    if not contact:
                        continue
                    email = (contact.get("email") or "").strip().lower()
                    if email and "@" in email and "registrar" not in email:
                        discovered_emails.add(email)
                    phone = (contact.get("telephone") or "").strip()
                    if phone:
                        metadata.setdefault("whois_phones", []).append(phone)
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("WhoisXML failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="WhoisXML WhoisService",
                response_preview=response_preview,
            )

    # 3b. WhoisXML Subdomains Lookup API
    if whoisxml_key:
        try:
            r = httpx.get(
                "https://subdomains.whoisxmlapi.com/api/v1",
                params={
                    "apiKey": whoisxml_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
                timeout=30,
            )
            if r.status_code == 200:
                sdata = r.json().get("result", {})
                records = sdata.get("records", [])
                sub_names = [rec.get("domain", "") for rec in records if rec.get("domain")]
                if sub_names:
                    metadata["whoisxml_subdomains"] = sub_names[:50]
                    for sub in sub_names[:30]:
                        cleaned = _clean_domain(sub)
                        if cleaned and cleaned != domain:
                            discovered_domains.add(cleaned)
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("WhoisXML Subdomains API failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="WhoisXML Subdomains",
                response_preview=response_preview,
            )

    # 3c. WhoisXML Website Contacts API — emails, phones, social links, company names
    if whoisxml_key:
        try:
            r = httpx.get(
                "https://website-contacts.whoisxmlapi.com/api/v1",
                params={
                    "apiKey": whoisxml_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
                timeout=30,
            )
            if r.status_code == 200:
                wc = r.json()
                company_names = wc.get("companyNames", [])
                if company_names:
                    metadata["website_company_names"] = company_names
                meta_block = wc.get("meta", {})
                if meta_block.get("title"):
                    metadata["website_title"] = meta_block["title"]
                if meta_block.get("description"):
                    metadata["website_description"] = meta_block["description"]
                social = wc.get("socialLinks", {})
                social_filtered = {k: v for k, v in social.items() if v}
                if social_filtered:
                    metadata["website_social_links"] = social_filtered
                for email_entry in wc.get("emails", []):
                    em = (email_entry.get("email") or "").strip().lower()
                    if em and "@" in em and "registrar" not in em:
                        discovered_emails.add(em)
                for phone_entry in wc.get("phones", []):
                    ph = (phone_entry.get("phoneNumber") or "").strip()
                    if ph:
                        metadata.setdefault("website_phones", []).append(ph)
                postal = wc.get("postalAddresses", [])
                if postal:
                    metadata["website_postal_addresses"] = postal[:5]
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("WhoisXML Website Contacts API failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="WhoisXML Website Contacts",
                response_preview=response_preview,
            )

    # 3d. WhoisXML SSL Certificates API — harvest SANs as additional domains
    if whoisxml_key:
        try:
            r = httpx.get(
                "https://ssl-certificates.whoisxmlapi.com/api/v1",
                params={
                    "apiKey": whoisxml_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
                timeout=30,
            )
            if r.status_code == 200:
                certs = r.json().get("certificates", [])
                if certs:
                    cert = certs[0]  # end-user certificate
                    san_names = (
                        cert.get("extensions", {})
                        .get("subjectAlternativeNames", {})
                        .get("dnsNames", [])
                    )
                    san_clean = [_clean_domain(n) for n in san_names if n and not n.startswith("*.")]
                    if san_clean:
                        metadata["ssl_san_domains"] = san_clean[:20]
                        for san in san_clean[:10]:
                            if san and san != domain:
                                discovered_domains.add(san)
                    cert_subject = cert.get("subject", {})
                    if cert_subject.get("organization"):
                        metadata["ssl_org"] = cert_subject["organization"]
                    metadata["ssl_valid_from"] = cert.get("validFrom")
                    metadata["ssl_valid_to"] = cert.get("validTo")
                    metadata["ssl_issuer"] = cert.get("issuer", {}).get("organization")
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("WhoisXML SSL Certificates API failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="WhoisXML SSL Certificates",
                response_preview=response_preview,
            )

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
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("SecurityTrails subdomains failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="SecurityTrails subdomains",
                response_preview=response_preview,
            )

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
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("SecurityTrails history failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="SecurityTrails history",
                response_preview=response_preview,
            )

        try:
            r = httpx.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/associated",
                headers={"APIKEY": sectrails_key},
                timeout=20,
            )
            if r.status_code == 200:
                assoc_records = r.json().get("records", [])
                assoc_domains = []
                for rec in assoc_records:
                    hostname = rec.get("hostname") or rec.get("name") or ""
                    if hostname and "." in hostname:
                        assoc_domains.append(hostname)
                metadata["securitytrails_associated"] = assoc_domains[:20]
                for ad in assoc_domains[:10]:
                    discovered_domains.add(ad)
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("SecurityTrails associated failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="SecurityTrails associated",
                response_preview=response_preview,
            )

    # 5. Hunter.io — company enrichment + domain search
    hunter_key = os.environ.get("HUNTER_API_KEY", "")
    if hunter_key:
        hunter_headers = {"X-API-KEY": hunter_key}

        # 5a. Company Enrichment
        try:
            r = httpx.get(
                "https://api.hunter.io/v2/companies/find",
                params={"domain": domain},
                headers=hunter_headers,
                timeout=15,
            )
            if r.status_code == 200:
                cdata = r.json().get("data", {})
                metadata["hunter_company_name"] = cdata.get("name")
                metadata["hunter_company_industry"] = cdata.get("industry")
                metadata["hunter_company_description"] = cdata.get("description")
                metadata["hunter_company_country"] = cdata.get("country")
                metadata["hunter_company_city"] = cdata.get("city")
                metadata["hunter_company_employees"] = cdata.get("employees")
                metadata["hunter_company_funding"] = cdata.get("funding_amount")
                tech = cdata.get("technologies", [])
                if tech:
                    metadata["hunter_company_tech"] = [
                        t.get("name") for t in tech[:20] if t.get("name")
                    ]
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("Hunter.io company enrichment failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="Hunter.io company enrichment",
                response_preview=response_preview,
            )

        # 5b. Domain Search — discover up to 10 emails on this domain
        hunter_emails: list[str] = []
        try:
            r = httpx.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "limit": 10},
                headers=hunter_headers,
                timeout=20,
            )
            if r.status_code == 200:
                dsdata = r.json().get("data", {})
                metadata["hunter_email_count"] = (dsdata.get("meta") or {}).get("total")
                for item in dsdata.get("emails", []):
                    em = (item.get("value") or "").strip().lower()
                    if em and "@" in em:
                        hunter_emails.append(em)
        except Exception as e:
            response_preview = _response_preview(getattr(e, "response", None))
            logger.warning("Hunter.io domain search failed for %s: %s", domain, e)
            log_scan_event(
                scan_id,
                "resolver_failed",
                resolver="resolve_domain",
                entity_key=node_id,
                error=str(e),
                service="Hunter.io domain search",
                response_preview=response_preview,
            )

        for em in hunter_emails:
            ek = _entity_key(EntityType.EMAIL.value, em)
            to_push.append({
                "type": EntityType.EMAIL.value,
                "value": em,
                "source": SOURCE,
                "confidence": 0.9,
                "depth": depth + 1,
                "parent_key": node_id,
            })
            edges_batch.append({
                "source": node_id,
                "target": ek,
                "relationship": "hunter_found_email",
                "confidence": 0.9,
            })

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

