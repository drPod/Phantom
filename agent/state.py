"""
GraphState: tracks the investigation graph, diffs against the Modal Dict for
new results, and produces deterministic compressed summaries (Tier 1).

The Analyst Claude now handles richer data analysis — this module only does
zero-cost, type-aware metadata collapsing for graph-context input.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from graph import EDGES_BATCH_PREFIX, NODE_PREFIX

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiffResult:
    """Immutable snapshot of what changed since the last sync."""

    new_nodes: list[dict[str, Any]]
    new_edges: list[dict[str, Any]]
    removed_keys: list[str]
    total_nodes: int
    total_edges: int


class GraphState:
    """Mirrors the Modal Dict, tracks diffs, and produces Tier 1 summaries."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._lock = threading.Lock()
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edge_batches: dict[str, list[dict[str, Any]]] = {}
        self._seen_keys: set[str] = set()
        self._resolved_pairs: set[str] = set()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(batch) for batch in self._edge_batches.values())

    # ------------------------------------------------------------------
    # Sync
    # ------------------------------------------------------------------

    def sync_from_dict(self, snapshot: dict[str, Any]) -> DiffResult:
        """Diff *snapshot* against previously seen state; update internal copy."""
        with self._lock:
            current_keys = set(snapshot.keys())
            prev_keys = set(self._seen_keys)

            new_keys = current_keys - prev_keys
            removed_keys = sorted(prev_keys - current_keys)

            new_nodes: list[dict[str, Any]] = []
            new_edges: list[dict[str, Any]] = []

            for key in sorted(current_keys):
                val = snapshot[key]
                if key.startswith(NODE_PREFIX) and isinstance(val, dict):
                    self._nodes[key] = val
                    if key in new_keys:
                        new_nodes.append(val)
                elif key.startswith(EDGES_BATCH_PREFIX) and isinstance(val, list):
                    self._edge_batches[key] = val
                    if key in new_keys:
                        new_edges.extend(val)

            for rk in removed_keys:
                self._nodes.pop(rk, None)
                self._edge_batches.pop(rk, None)

            self._seen_keys = current_keys

            return DiffResult(
                new_nodes=new_nodes,
                new_edges=new_edges,
                removed_keys=removed_keys,
                total_nodes=self.node_count,
                total_edges=self.edge_count,
            )

    # ------------------------------------------------------------------
    # Resolved-pair tracking
    # ------------------------------------------------------------------

    def mark_resolved(self, resolver: str, entity_key: str) -> None:
        """Record that *resolver* has been run on *entity_key*."""
        with self._lock:
            self._resolved_pairs.add(f"{resolver}:{entity_key}")

    def is_resolved(self, resolver: str, entity_key: str) -> bool:
        """Check whether *resolver* has already been run on *entity_key*."""
        with self._lock:
            return f"{resolver}:{entity_key}" in self._resolved_pairs

    def resolved_entity_keys(self) -> set[str]:
        """Return the set of entity_keys that have been attempted by any resolver."""
        with self._lock:
            result: set[str] = set()
            for pair in self._resolved_pairs:
                # pairs are stored as "resolver_name:entity_key"
                # entity_key itself may contain ":" (e.g. "username:torvalds")
                # so split on first ":" only gives resolver, not entity_key
                # use the known resolver names as a split guide:
                idx = pair.find(":")
                if idx != -1:
                    result.add(pair[idx + 1:])
            return result

    # ------------------------------------------------------------------
    # Public summary methods
    # ------------------------------------------------------------------

    def full_summary(self) -> str:
        """Deterministic Tier 1 compressed summary of the entire graph."""
        with self._lock:
            all_nodes = list(self._nodes.values())
            all_edges = self._all_edges()
            return self._tier1_summary(all_nodes, all_edges, label="FULL")

    def diff_summary(self, diff: DiffResult) -> str:
        """Deterministic Tier 1 compressed summary of what changed."""
        if not diff.new_nodes and not diff.new_edges and not diff.removed_keys:
            return "DIFF: no changes"
        with self._lock:
            return self._tier1_summary(
                diff.new_nodes, diff.new_edges, label="DIFF",
                extra_header=self._diff_header(diff),
            )

    # ------------------------------------------------------------------
    # Tier 1 — deterministic compression
    # ------------------------------------------------------------------

    def _compress_node(self, node: dict[str, Any]) -> str:
        ntype = node.get("type", "unknown")
        value = node.get("value", "?")
        depth = node.get("depth", 0)
        meta = node.get("metadata") or {}
        nid = node.get("id", f"{ntype}:{value}")

        meta_str = self._compress_metadata(ntype, meta)
        return f"{nid} d={depth} | {meta_str}" if meta_str else f"{nid} d={depth}"

    def _compress_metadata(self, entity_type: str, meta: dict[str, Any]) -> str:
        if not meta:
            return ""
        if entity_type == "email":
            return self._compress_email_meta(meta)
        if entity_type == "username":
            return self._compress_username_meta(meta)
        if entity_type == "domain":
            return self._compress_domain_meta(meta)
        if entity_type == "platform_profile":
            return self._compress_platform_meta(meta)
        return self._compress_generic_meta(meta)

    # -- email --

    def _compress_email_meta(self, m: dict[str, Any]) -> str:
        parts: list[str] = []

        rep = m.get("emailrep_reputation")
        if rep:
            parts.append(f"rep={rep}")

        breach_ct = m.get("hibp_breach_count")
        if breach_ct is not None:
            breach_names = [
                b.get("name", "?")
                for b in (m.get("hibp_breach_detail") or [])[:3]
            ]
            if breach_names:
                parts.append(f"br={breach_ct}({','.join(breach_names)})")
            else:
                parts.append(f"br={breach_ct}")

        paste_ct = m.get("hibp_paste_count")
        if paste_ct:
            parts.append(f"pastes={paste_ct}")

        disp = m.get("disposable")
        if disp is None:
            disp = m.get("whoisxml_email_disposable")
        if disp is not None:
            parts.append(f"disp={'y' if disp else 'n'}")

        smtp = m.get("hunter_smtp_check")
        if smtp is None:
            smtp = m.get("whoisxml_email_smtp_valid")
        if smtp is not None:
            parts.append(f"smtp={'ok' if smtp else 'fail'}")

        hscore = m.get("hunter_score")
        if hscore is not None:
            parts.append(f"hscore={hscore}")

        grav = m.get("gravatar_username")
        if grav:
            parts.append(f"grav={grav}")

        profiles = m.get("emailrep_profiles") or []
        if profiles:
            parts.append(f"prof=[{','.join(str(p) for p in profiles[:5])}]")

        name = m.get("hunter_full_name")
        if name:
            parts.append(f'name="{name}"')

        company = m.get("hunter_company")
        if company:
            parts.append(f"co={company}")

        location_parts = [
            p for p in [m.get("hunter_city"), m.get("hunter_country")] if p
        ]
        if location_parts:
            parts.append(f"loc={'/'.join(location_parts)}")

        cred_leaked = m.get("emailrep_credentials_leaked")
        if cred_leaked:
            parts.append("CREDS_LEAKED")

        suspicious = m.get("emailrep_suspicious")
        if suspicious:
            parts.append("SUSPICIOUS")

        stealer = m.get("hibp_stealer_log_domains") or []
        if stealer:
            parts.append(f"stealer_domains={len(stealer)}")

        dehashed = m.get("dehashed_total")
        if dehashed:
            parts.append(f"dehashed={dehashed}")

        leakcheck = m.get("leakcheck_found")
        if leakcheck:
            lc_sources = [
                s.get("name", "?")
                for s in (m.get("leakcheck_sources") or [])[:3]
            ]
            parts.append(f"leakcheck={leakcheck}({','.join(lc_sources)})")

        return " ".join(parts)

    # -- username --

    def _compress_username_meta(self, m: dict[str, Any]) -> str:
        parts: list[str] = []

        login = m.get("login")
        if login:
            parts.append(f"gh={login}")

        bio = m.get("bio")
        if bio:
            bio_short = bio[:80].replace("\n", " ").strip()
            parts.append(f'bio="{bio_short}"')

        repos = m.get("public_repos") or m.get("repo_count")
        if repos is not None:
            parts.append(f"repos={repos}")

        followers = m.get("followers")
        if followers is not None:
            parts.append(f"follow={followers}")

        orgs = m.get("organizations") or []
        if orgs:
            parts.append(f"orgs=[{','.join(orgs[:5])}]")

        name = m.get("name")
        if name:
            parts.append(f'name="{name}"')

        company = m.get("company")
        if company:
            parts.append(f"co={company}")

        location = m.get("location")
        if location:
            parts.append(f"loc={location}")

        commit_emails = m.get("commit_emails_found")
        if commit_emails:
            parts.append(f"commit_emails={commit_emails}")

        sites_checked = m.get("sites_checked")
        hits_count = m.get("hits_count")
        if sites_checked is not None and hits_count is not None:
            profiles = m.get("confirmed_profiles") or []
            site_names = [p.get("site_name", "?") for p in profiles[:5]]
            parts.append(
                f"platforms={hits_count}/{sites_checked}"
                + (f"[{','.join(site_names)}]" if site_names else "")
            )

        reddit_karma = m.get("reddit_karma")
        if reddit_karma is not None:
            parts.append(f"reddit_karma={reddit_karma}")

        reddit_bio = m.get("reddit_bio")
        if reddit_bio:
            parts.append(f'reddit_bio="{reddit_bio[:60]}"')

        reddit_interests = m.get("reddit_inferred_interests")
        if reddit_interests:
            parts.append(f"reddit_interests=[{','.join(str(i) for i in reddit_interests[:5])}]")

        reddit_profession = m.get("reddit_inferred_profession")
        if reddit_profession:
            parts.append(f"reddit_prof={str(reddit_profession)[:60]}")

        reddit_location = m.get("reddit_inferred_location")
        if reddit_location:
            parts.append(f"reddit_loc={str(reddit_location)[:40]}")

        reddit_partners = m.get("reddit_frequent_partners")
        if reddit_partners:
            top_partners = list(reddit_partners.keys())[:3] if isinstance(reddit_partners, dict) else []
            parts.append(f"reddit_partners={len(reddit_partners)}" + (f"[{','.join(top_partners)}]" if top_partners else ""))

        reddit_identity = m.get("reddit_identity_signals") or []
        if reddit_identity:
            parts.append(f"reddit_id_signals={len(reddit_identity)}[{','.join(str(s)[:30] for s in reddit_identity[:3])}]")

        reddit_subs = m.get("reddit_subreddit_distribution")
        if reddit_subs:
            top_subs = list(reddit_subs.keys())[:5] if isinstance(reddit_subs, dict) else []
            parts.append(f"reddit_subs={len(reddit_subs)}[{','.join(top_subs)}]")

        kb_user = m.get("keybase_username")
        if kb_user:
            linked = m.get("keybase_linked_accounts") or []
            services = [a.get("service", "?") for a in linked[:5]]
            verified_count = sum(1 for a in linked if a.get("verified"))
            parts.append(f"keybase={kb_user}[{','.join(services)}] verified={verified_count}/{len(linked)}")

        pgp = m.get("pgp_keys") or []
        if pgp:
            pgp_emails = [k.get("email", "?") for k in pgp[:3]]
            parts.append(f"pgp=[{','.join(pgp_emails)}]")

        hn_karma = m.get("hn_karma")
        if hn_karma is not None:
            parts.append(f"hn_karma={hn_karma}")

        hn_about = m.get("hn_about")
        if hn_about:
            parts.append(f'hn_about="{str(hn_about)[:60]}"')

        hn_stories = m.get("hn_story_count")
        hn_comments = m.get("hn_comment_count")
        if hn_stories is not None or hn_comments is not None:
            parts.append(f"hn_activity=stories:{hn_stories or 0}/comments:{hn_comments or 0}")

        hn_domains = m.get("hn_top_domains")
        if hn_domains:
            top_hn_domains = list(hn_domains.keys())[:3] if isinstance(hn_domains, dict) else []
            parts.append(f"hn_domains=[{','.join(top_hn_domains)}]")

        so_rep = m.get("so_reputation")
        if so_rep is not None:
            parts.append(f"so_rep={so_rep}")

        so_tags = m.get("so_top_tags")
        if so_tags:
            tag_names = [t.get("tag_name", "?") for t in so_tags[:5]]
            parts.append(f"so_tags=[{','.join(tag_names)}]")

        so_sites = m.get("so_associated_sites")
        if so_sites:
            site_names = [s.get("site_name", "?") for s in so_sites[:5]]
            parts.append(f"so_sites={len(so_sites)}[{','.join(site_names)}]")

        so_link = m.get("so_profile_link")
        if so_link:
            parts.append(f"so_link={so_link}")

        gists = m.get("gists") or []
        if gists:
            parts.append(f"gists={len(gists)}")

        follower_sample = m.get("followers_sample") or []
        if follower_sample:
            parts.append(f"gh_followers_sample={len(follower_sample)}")

        return " ".join(parts)

    # -- domain --

    def _compress_domain_meta(self, m: dict[str, Any]) -> str:
        parts: list[str] = []

        registrar = m.get("whois_registrar")
        if registrar:
            parts.append(f"reg={registrar}")

        created = m.get("whois_created_date")
        if created:
            parts.append(f"created={str(created)[:10]}")

        age = m.get("whois_estimated_age_days")
        if age is not None:
            parts.append(f"age={age}d")

        reg_org = m.get("whois_registrant_org")
        if reg_org:
            parts.append(f"org={reg_org}")

        reg_country = m.get("whois_registrant_country_code") or m.get(
            "whois_registrant_country"
        )
        if reg_country:
            parts.append(f"country={reg_country}")

        crt_subs = m.get("crt_sh_subdomains") or []
        whois_subs = m.get("whoisxml_subdomains") or []
        st_subs = m.get("securitytrails_subdomains") or []
        all_subs = list(set(crt_subs + whois_subs + st_subs))
        if all_subs:
            parts.append(
                f"subs={len(all_subs)}[{','.join(all_subs[:4])}]"
            )

        dns_a = m.get("dns_a") or []
        if dns_a:
            parts.append(f"A=[{','.join(dns_a[:3])}]")

        dns_mx = m.get("dns_mx") or []
        if dns_mx:
            parts.append(f"MX=[{','.join(dns_mx[:3])}]")

        ssl_org = m.get("ssl_org")
        if ssl_org:
            parts.append(f"ssl_org={ssl_org}")

        ssl_issuer = m.get("ssl_issuer")
        if ssl_issuer:
            parts.append(f"ssl_issuer={ssl_issuer}")

        hunter_co = m.get("hunter_company_name")
        if hunter_co:
            parts.append(f"hunter_co={hunter_co}")

        hunter_industry = m.get("hunter_company_industry")
        if hunter_industry:
            parts.append(f"industry={hunter_industry}")

        hunter_emails = m.get("hunter_email_count")
        if hunter_emails is not None:
            parts.append(f"hunter_emails={hunter_emails}")

        st_assoc = m.get("securitytrails_associated") or []
        if st_assoc:
            parts.append(f"assoc={len(st_assoc)}[{','.join(st_assoc[:3])}]")

        st_hist_ips = m.get("securitytrails_historical_ips") or []
        if st_hist_ips:
            parts.append(f"hist_ips={len(st_hist_ips)}")

        social = m.get("website_social_links") or {}
        if social:
            links = [f"{k}={v}" for k, v in list(social.items())[:3]]
            parts.append(f"social=[{','.join(links)}]")

        return " ".join(parts)

    # -- platform_profile --

    def _compress_platform_meta(self, m: dict[str, Any]) -> str:
        parts: list[str] = []
        site = m.get("site_name")
        if site:
            parts.append(f"site={site}")
        cat = m.get("category")
        if cat:
            parts.append(f"cat={cat}")
        name = m.get("display_name")
        if name:
            parts.append(f'name="{str(name)[:40]}"')
        bio = m.get("bio_snippet")
        if bio:
            parts.append(f'bio="{str(bio)[:60]}"')
        if m.get("avatar_url"):
            parts.append("avatar=yes")
        followers = m.get("follower_count")
        if followers is not None:
            parts.append(f"followers={followers}")
        joined = m.get("join_date")
        if joined:
            parts.append(f"joined={str(joined)[:20]}")
        links = m.get("linked_urls") or []
        if links:
            parts.append(f"links={len(links)}")
        if m.get("identity_mismatch"):
            parts.append("MISMATCH")
        # Fallback for old-format nodes that still have og_title/og_description
        og = m.get("og_title") or m.get("og_description")
        if og and not name:
            parts.append(f'og="{str(og)[:60]}"')
        return " ".join(parts)

    # -- generic fallback --

    def _compress_generic_meta(self, m: dict[str, Any]) -> str:
        parts: list[str] = []
        for k, v in list(m.items())[:8]:
            if v is None:
                continue
            if isinstance(v, str):
                parts.append(f"{k}={v[:40]}")
            elif isinstance(v, (int, float, bool)):
                parts.append(f"{k}={v}")
            elif isinstance(v, list):
                parts.append(f"{k}={len(v)}items")
            elif isinstance(v, dict):
                parts.append(f"{k}={{...}}")
        return " ".join(parts)

    # -- edges --

    def _summarize_edges(self, edges: list[dict[str, Any]]) -> str:
        if not edges:
            return ""
        groups: dict[str, int] = defaultdict(int)
        for e in edges:
            src = e.get("source", "?")
            rel = e.get("relationship", "linked_to")
            groups[f"{src}--{rel}"] += 1

        sorted_groups = sorted(groups.items(), key=lambda x: -x[1])
        shown = sorted_groups[:8]
        remainder = sum(c for _, c in sorted_groups[8:])

        parts = [f"{key}({count})" for key, count in shown]
        if remainder:
            parts.append(f"+{remainder} more")
        return " | ".join(parts)

    # -- tier 1 assembly --

    def _tier1_summary(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        label: str = "GRAPH",
        extra_header: str = "",
    ) -> str:
        if not nodes and not edges:
            return f"{label}: empty"

        depths = [n.get("depth", 0) for n in nodes] if nodes else [0]
        header = (
            f"{label}: {len(nodes)} nodes, {len(edges)} edges, "
            f"depth {min(depths)}-{max(depths)}"
        )
        if extra_header:
            header = f"{header}\n{extra_header}"

        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for n in nodes:
            by_type[n.get("type", "unknown")].append(n)

        type_order = ["username", "email", "domain", "platform_profile"]
        ordered_types = [t for t in type_order if t in by_type]
        ordered_types += sorted(set(by_type.keys()) - set(type_order))

        sections: list[str] = [header]
        for ntype in ordered_types:
            type_nodes = by_type[ntype]
            section_lines = [f"--- {ntype.upper()} ({len(type_nodes)}) ---"]
            for node in type_nodes:
                section_lines.append(self._compress_node(node))
            sections.append("\n".join(section_lines))

        if edges:
            sections.append(f"--- EDGES ({len(edges)}) ---\n{self._summarize_edges(edges)}")

        resolved = self._resolved_section()
        if resolved:
            sections.append(resolved)

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolved_section(self) -> str:
        """Deterministic listing of every resolver:entity pair already run."""
        if not self._resolved_pairs:
            return ""
        by_resolver: dict[str, list[str]] = defaultdict(list)
        for pair in self._resolved_pairs:
            resolver, _, entity_key = pair.partition(":")
            by_resolver[resolver].append(entity_key)
        lines = [f"--- RESOLVERS ALREADY COMPLETED ({len(self._resolved_pairs)}) ---"]
        for resolver in sorted(by_resolver):
            entities = ", ".join(sorted(by_resolver[resolver]))
            lines.append(f"{resolver}: {entities}")
        return "\n".join(lines)

    def _all_edges(self) -> list[dict[str, Any]]:
        edges: list[dict[str, Any]] = []
        for batch in self._edge_batches.values():
            edges.extend(batch)
        return edges

    def _diff_header(self, diff: DiffResult) -> str:
        parts = [f"+{len(diff.new_nodes)} nodes", f"+{len(diff.new_edges)} edges"]
        if diff.removed_keys:
            parts.append(f"-{len(diff.removed_keys)} keys")
        parts.append(f"(total: {diff.total_nodes}N/{diff.total_edges}E)")
        return " ".join(parts)
