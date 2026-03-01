"""Claude tool_use schemas for OSINT resolvers.

Each resolver is expressed as an Anthropic ToolParam dict so the LLM can
request resolver invocations via tool_use blocks.  The orchestrator maps
tool names back to Modal function handles at dispatch time.
"""

from __future__ import annotations

from typing import Any


def _common_properties(entity_type_enum: list[str]) -> dict[str, Any]:
    """Shared input_schema properties for every resolver tool."""
    return {
        "entity_value": {
            "type": "string",
            "description": "The raw identifier to investigate (e.g. a username, email address, or domain).",
        },
        "entity_type": {
            "type": "string",
            "enum": entity_type_enum,
            "description": "Entity category that this resolver accepts.",
        },
        "depth": {
            "type": "integer",
            "minimum": 0,
            "description": "Number of hops from the seed entity in the current scan graph.",
        },
        "source_entity_key": {
            "type": "string",
            "description": "Entity key of the parent node that led to this investigation (e.g. 'username:johndoe').",
        },
        "scan_id": {
            "type": "string",
            "description": "Unique scan identifier used to route results to the correct Modal Queue/Dict.",
        },
    }


_REQUIRED = ["entity_value", "entity_type", "depth", "source_entity_key", "scan_id"]


def _tool(
    name: str,
    description: str,
    entity_types: list[str],
) -> dict[str, Any]:
    """Build a single Anthropic ToolParam dict."""
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": _common_properties(entity_types),
            "required": _REQUIRED,
        },
    }


# ---------------------------------------------------------------------------
# Tool definitions – one per resolver
# ---------------------------------------------------------------------------

RESOLVE_GITHUB = _tool(
    name="resolve_github",
    description=(
        "Lightweight GitHub profile probe: public email, blog URL, bio. "
        "Surfaces: emails, domains."
    ),
    entity_types=["username"],
)


ENUMERATE_USERNAME = _tool(
    name="enumerate_username",
    description=(
        "Username existence check across ~600 sites (WhatsMyName). Returns confirmed "
        "profile URLs with scraped display names, bios, avatars, follower counts. "
        "Leaf resolver — does NOT discover new entities. "
        "A hit count of 10+ signals a strong, consistent handle worth deep-diving "
        "with resolve_social."
    ),
    entity_types=["username"],
)

RESOLVE_SOCIAL = _tool(
    name="resolve_social",
    description=(
        "Deep social presence: Reddit (comment history, subreddit patterns, "
        "interest/profession/location inference), Keybase (cryptographic proofs "
        "linking platform handles), Hacker News (profile + activity), Stack Overflow "
        "(profile, top tags, cross-site accounts), PGP key servers. "
        "Surfaces: emails, domains, wallets, cross-platform usernames (especially "
        "Keybase proofs — these are verified identity links). "
        "Chain: investigate each Keybase-linked handle not already in the graph."
    ),
    entity_types=["username"],
)

RESOLVE_EMAIL = _tool(
    name="resolve_email",
    description=(
        "Email enrichment: Kickbox deliverability, WhoisXML verification, Gravatar "
        "profile, Hunter.io (name, company, position, LinkedIn/Twitter/GitHub links), "
        "EmailRep reputation (credential leak flags, malicious activity), HIBP "
        "(breach names, paste count, stealer log domains). "
        "Surfaces: usernames (Gravatar preferredUsername, Hunter social handles, "
        "EmailRep profiles), domains (Hunter email domain). "
        "Chain: if HIBP breaches found, run resolve_breach on the same email; "
        "if Gravatar username or Hunter social handle found, run "
        "resolve_social + enumerate_username on that username."
    ),
    entity_types=["email"],
)

RESOLVE_BREACH = _tool(
    name="resolve_breach",
    description=(
        "Breach database deep-dive: Dehashed, LeakCheck, BreachDirectory. Returns "
        "breach names, dates, hashed passwords, associated IPs, phones, and names "
        "from breach entries. "
        "Surfaces: emails and usernames found in the same breach records. "
        "Chain: run resolve_email or resolve_social on the most relevant surfaced "
        "identifiers."
    ),
    entity_types=["email", "username"],
)

RESOLVE_DOMAIN = _tool(
    name="resolve_domain",
    description=(
        "Domain intelligence: crt.sh subdomains, DNS (A/MX/TXT/NS), WHOIS "
        "registrant data, WhoisXML subdomain enumeration, website contact scraping, "
        "SSL certificate SANs, SecurityTrails historical DNS and associated domains, "
        "Hunter.io email patterns and company enrichment. "
        "Surfaces: emails (WHOIS contacts, website contacts, Hunter domain search), "
        "domains (subdomains, MX hosts, SSL SANs, SecurityTrails associated). "
        "Chain: run resolve_email on Hunter-found emails (skip generic role addresses "
        "like info@, admin@, support@)."
    ),
    entity_types=["domain"],
)

RESOLVE_PHONE = _tool(
    name="resolve_phone",
    description=(
        "Investigate a phone number using Numverify and Veriphone APIs. "
        "Returns carrier, line type (mobile/landline/VoIP/toll-free/premium), "
        "geographic location or region, country, country code, and "
        "international E.164 formatting. This is a leaf resolver — it "
        "enriches the phone node but does not discover new entities to "
        "investigate."
    ),
    entity_types=["phone"],
)

RESOLVE_WALLET = _tool(
    name="resolve_wallet",
    description=(
        "Investigate a cryptocurrency wallet address. For Ethereum (0x…) "
        "addresses: current ETH balance, recent normal transactions, and "
        "ERC-20 token transfers via Etherscan. For Bitcoin (1…/3…/bc1…) "
        "addresses: balance, total received/sent, transaction count, and "
        "recent transaction history via Blockchain.com. Discovers up to "
        "five unique counterparty wallet addresses from transaction history "
        "and emits them as new wallet entities."
    ),
    entity_types=["wallet"],
)

CORRELATE_IDENTITIES: dict[str, Any] = {
    "name": "correlate_identities",
    "description": (
        "Run GPU-backed cross-platform identity correlation across all nodes "
        "currently in the scan graph.  Compares display names, bios, and "
        "metadata for same-type nodes and emits 'likely_same_person' edges "
        "between profiles that score >= 0.75 on the identity-match model.  "
        "Call this after a cluster of related usernames or platform profiles "
        "has been discovered to surface hidden identity links before continuing "
        "the investigation.  Only scan_id is required; all other fields are "
        "ignored."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "string",
                "description": "Unique scan identifier used to route results to the correct Modal Dict.",
            },
        },
        "required": ["scan_id"],
    },
}

FINISH_INVESTIGATION: dict[str, Any] = {
    "name": "finish_investigation",
    "description": (
        "Call this tool when the investigation is complete — either all "
        "productive leads have been exhausted, depth/entity limits are "
        "reached, or remaining entities are low-value. Provide a short "
        "reason summarising why you are stopping."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "Brief explanation for why the investigation is finished.",
            },
        },
        "required": ["reason"],
    },
}

# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

RESOLVER_TOOLS: list[dict[str, Any]] = [
    RESOLVE_GITHUB,
    ENUMERATE_USERNAME,
    RESOLVE_SOCIAL,
    RESOLVE_EMAIL,
    RESOLVE_BREACH,
    RESOLVE_DOMAIN,
    RESOLVE_PHONE,
    RESOLVE_WALLET,
    CORRELATE_IDENTITIES,
]

ALL_TOOLS: list[dict[str, Any]] = RESOLVER_TOOLS + [FINISH_INVESTIGATION]

TOOL_NAME_TO_RESOLVER: dict[str, str] = {
    "resolve_github": "resolvers.username.resolve_github",
    "enumerate_username": "resolvers.username_enum.enumerate_username",
    "resolve_social": "resolvers.social.resolve_social",
    "resolve_email": "resolvers.email.resolve_email",
    "resolve_breach": "resolvers.breach.resolve_breach",
    "resolve_domain": "resolvers.domain.resolve_domain",
    "resolve_phone": "resolvers.phone.resolve_phone",
    "resolve_wallet": "resolvers.wallet.resolve_wallet",
    "correlate_identities": "resolvers.identity_correlator.correlate_identities_tool",
}
