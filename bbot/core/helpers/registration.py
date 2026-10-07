"""
Shared pieces of a domain registration record.

WHOIS and RDAP answer the same question over different protocols, so the record they produce and the
rules for reading it (dates, redaction, privacy proxies) live here rather than in either backend.
"""

import re
from datetime import datetime

from .validators import is_email
from bbot.models.helpers import utc_datetime_validator

# names of privacy/proxy services that registrars put in place of the registrant
# these are specific phrases rather than bare words like "privacy", which also appear in real organization names
_PROXY_SERVICE_PATTERNS = (
    r"privacy\s*(service|protect|guard)",
    r"(contact|whois|domain|perfect|super)\s*privacy",
    r"(domain|identity|whois|privacy)\s*protection",
    r"whois\s*guard",
    r"by proxy",
    r"proxy\s*service",
    r"registration private",
    r"private by design",
    r"^on behalf of",
)
_PROXY_SERVICE_REGEX = re.compile(r"|".join(_PROXY_SERVICE_PATTERNS), re.I)
_PLACEHOLDER_REGEX = re.compile(
    r"|".join(
        _PROXY_SERVICE_PATTERNS
        + (
            r"redact",
            r"withheld",
            r"data protected",
            r"not disclosed",
            r"statutory masking",
            r"gdpr",
            r"request email form",
            r"^hidden$",
            r"^n/?a$",
            r"^none$",
        )
    ),
    re.I,
)
# placeholder emails are matched separately on the local part and the domain, so that e.g.
# "privacy@apple.com" (a real address) isn't mistaken for "x.protect@withheldforprivacy.com"
_PLACEHOLDER_EMAIL_LOCAL_REGEX = re.compile(r"redact|withheld|whois\s*guard|(^|[._-])protect$", re.I)
_PLACEHOLDER_EMAIL_DOMAIN_REGEX = re.compile(
    r"redact|withheld|whoisguard|byproxy|contactprivacy|privacyguardian|privacyprotect|whoisprivacy"
    r"|privacyservice|domainprotect|identityprotect|privatebydesign",
    re.I,
)
# fromisoformat() is strict about fraction digits and compact offsets; RDAP timestamps use both
_FRACTION_REGEX = re.compile(r"(\.\d+)")
_COMPACT_OFFSET_REGEX = re.compile(r"(T[\d:.]+[+-]\d{2})(\d{2})$")

REGISTRANT_FIELDS = ("registrant_org", "registrant_name", "registrant_email", "registrant_country")


def is_placeholder(value):
    """
    Return True if a registrant value is a privacy/redaction placeholder rather than real data.

    Examples:
        >>> is_placeholder("REDACTED FOR PRIVACY")
        True
        >>> is_placeholder("GitHub, Inc.")
        False
    """
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value:
        return False
    if is_email(value):
        local, _, domain = value.rpartition("@")
        return bool(_PLACEHOLDER_EMAIL_LOCAL_REGEX.search(local) or _PLACEHOLDER_EMAIL_DOMAIN_REGEX.search(domain))
    return bool(_PLACEHOLDER_REGEX.search(value))


def is_proxy_service(value):
    """
    Return True if a registrant value names a privacy/proxy service (rather than just being redacted).

    The contact details of a proxy service (e.g. its address) belong to the service, not the registrant.

    Examples:
        >>> is_proxy_service("Domains By Proxy, LLC")
        True
        >>> is_proxy_service("REDACTED FOR PRIVACY")
        False
    """
    if not isinstance(value, str) or "@" in value:
        return False
    return bool(_PROXY_SERVICE_REGEX.search(value.strip()))


def parse_registration_date(value):
    """
    Normalize a registration timestamp to a UTC ISO-8601 string like "2007-10-09T18:20:50Z".

    Accepts datetimes (naive ones are assumed UTC) and ISO-8601/RFC-3339 strings, including "Z",
    numeric offsets, and any number of fraction digits. Returns None if the value can't be parsed.

    Examples:
        >>> parse_registration_date("2001-01-13T02:12:14.754+02:00")
        '2001-01-13T00:12:14Z'
        >>> parse_registration_date("2026-08-12T08:47:19.41Z")
        '2026-08-12T08:47:19Z'
    """
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        if value[-1] in "zZ":
            value = value[:-1] + "+00:00"
        value = _FRACTION_REGEX.sub(lambda m: m.group(1)[:7].ljust(7, "0"), value, count=1)
        value = _COMPACT_OFFSET_REGEX.sub(r"\1:\2", value)
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return utc_datetime_validator(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def clean(value):
    value = next(iter(as_list(value)), None)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def apply_registrant(record, raw_org=None, raw_name=None, raw_email=None, raw_country=None):
    """
    Add registrant fields to `record`, dropping privacy placeholders and setting registrant_redacted.

    Redaction is per-field, so e.g. a redacted name can still come with a real organization. If the
    registrant is a privacy service, its address (and therefore country) belongs to the service.
    """
    for field, value in (
        ("registrant_org", raw_org),
        ("registrant_name", raw_name),
        ("registrant_email", raw_email),
        ("registrant_country", raw_country),
    ):
        if not value:
            continue
        if is_placeholder(value):
            record["registrant_redacted"] = True
            continue
        record[field] = value
    if is_proxy_service(raw_org) or (not record.get("registrant_org") and is_proxy_service(raw_name)):
        record.pop("registrant_country", None)
    if record.get("registrant_email"):
        record["registrant_email"] = record["registrant_email"].lower()
    country = record.get("registrant_country")
    if country and len(country) == 2:
        record["registrant_country"] = country.upper()
    return record
