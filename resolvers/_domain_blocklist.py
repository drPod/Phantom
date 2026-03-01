"""Domains that should never be pushed to the resolution queue.

Combines two sources:
  1. `disposable-email-domains` PyPI package (~4 000 community-vetted disposable /
     temporary email domains, updated continuously).
  2. A hardcoded set of major free-email providers (Gmail, Yahoo, Outlook, etc.)
     that are *not* disposable per se, but are meaningless to resolve as OSINT
     domain targets.
"""

import logging

logger = logging.getLogger(__name__)

# fmt: off
_FREE_EMAIL_PROVIDERS: frozenset[str] = frozenset({
    # Google / Apple
    "gmail.com", "googlemail.com",
    "icloud.com", "me.com", "mac.com",

    # Microsoft
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
    "hotmail.es", "hotmail.it", "hotmail.com.br", "hotmail.com.ar", "hotmail.com.mx",
    "outlook.com",
    "live.com", "live.co.uk", "live.fr", "live.de", "live.ca",
    "live.nl", "live.it", "live.com.au", "live.com.ar", "live.com.mx", "live.co.in",
    "msn.com", "passport.com",

    # Yahoo
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "yahoo.ca", "yahoo.es", "yahoo.it", "yahoo.com.au", "yahoo.com.br",
    "yahoo.com.mx", "yahoo.com.ar", "yahoo.co.jp", "yahoo.com.ph",
    "ymail.com", "rocketmail.com",

    # AOL
    "aol.com", "aol.co.uk", "aim.com", "verizon.net",

    # Privacy / Encrypted providers
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    "tutanota.com", "tutanota.de", "tutanota.org", "tutamail.com", "tuta.io", "keemail.me",
    "posteo.de", "posteo.net", "posteo.org",
    "mailfence.com", "disroot.org", "startmail.com",
    "fastmail.com", "fastmail.fm", "fastmail.net", "fastmail.to", "fastmail.org",
    "riseup.net", "autistici.org", "inventati.org",
    "cock.li", "airmail.cc",

    # GMX
    "gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch",
    "gmx.fr", "gmx.us", "gmx.org", "gmx.co.uk",

    # Mail.com group
    "mail.com", "email.com", "inbox.com",

    # Yandex / Russian
    "yandex.com", "yandex.ru", "yandex.net", "yandex.kz", "yandex.ua",
    "ya.ru", "mail.ru", "internet.ru", "bk.ru", "list.ru", "inbox.ru",

    # Chinese
    "qq.com", "163.com", "126.com", "139.com",
    "sina.com", "sina.cn", "sohu.com", "aliyun.com",

    # German
    "web.de", "t-online.de", "freenet.de", "mail.de",

    # French
    "free.fr", "laposte.net", "orange.fr", "wanadoo.fr",
    "sfr.fr", "bbox.fr",

    # Italian
    "libero.it", "virgilio.it", "tiscali.it",

    # Polish
    "wp.pl", "op.pl", "interia.pl", "o2.pl", "onet.pl",

    # Indian
    "rediffmail.com", "sify.com",

    # Zoho
    "zoho.com", "zohomail.com", "zohomail.in",

    # noreply / system
    "noreply.com",
    "noreply.github.com",
    "users.noreply.github.com",
    "notifications.github.com",
    "no-reply.accounts.google.com",
    "no-reply.github.com",

    # Placeholder / test
    "domain.com", "example.com", "example.org", "example.net",
    "test.com", "test.org", "test.net",
    "localhost", "local", "invalid",
    "placeholder.com", "dummy.com", "fake.com", "nowhere.com", "none.com",
})
# fmt: on


def _load_blocklist() -> frozenset[str]:
    try:
        from disposable_email_domains import blocklist as _disposable  # type: ignore[import-untyped]
        return frozenset(_disposable) | _FREE_EMAIL_PROVIDERS
    except ImportError as e:
        # Package not installed (e.g. local dev without Modal deps) — fall back to
        # the hardcoded list so the module always exports a usable set.
        logger.warning(
            "disposable_email_domains package not available (blocklist fallback); %s",
            e,
            exc_info=True,
        )
        return _FREE_EMAIL_PROVIDERS


BLOCKED_DOMAINS: frozenset[str] = _load_blocklist()
