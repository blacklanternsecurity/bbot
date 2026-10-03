"""
WHOIS lookups for domain registration data, backed by python-whois.

Parsing lives in module-level functions so it can be used on raw WHOIS text without a scan.
"""

import re
import asyncio
import logging
from datetime import datetime, timezone

import whois as python_whois
from whois.parser import WhoisEntry
from whois.exceptions import PywhoisError

log = logging.getLogger("bbot.core.helpers.whois")


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
# EPP status codes come with a trailing ICANN link, e.g. "clientDeleteProhibited https://icann.org/epp#..."
_STATUS_CODE_REGEX = re.compile(r"^([A-Za-z]+)")
_CAMEL_REGEX = re.compile(r"(?<=[a-z])(?=[A-Z])")
_IANA_ID_REGEX = re.compile(r"^\s*Registrar IANA ID:\s*(\d+)", re.I | re.M)
_REGISTRANT_EMAIL_REGEX = re.compile(r"^\s*Registrant Email:\s*(\S+@\S+)", re.I | re.M)


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
    if "@" in value and " " not in value:
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


def parse_whois_date(value):
    """
    Normalize a WHOIS date to a UTC ISO-8601 string like "2007-10-09T18:20:50Z".

    Accepts datetimes (naive ones are assumed UTC) and ISO-8601 strings. Returns None if the value can't be parsed.

    Examples:
        >>> parse_whois_date("2001-01-13T02:12:14.754+02:00")
        '2001-01-13T00:12:14Z'
    """
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        if value[-1] in "zZ":
            value = value[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _dates(value):
    return [d for d in map(parse_whois_date, _as_list(value)) if d]


def _first_date(value):
    """Thick WHOIS repeats dates (registry first, then registrar, often truncated to midnight). Keep the registry's."""
    return next(iter(_dates(value)), None)


def _latest_date(value):
    return max(_dates(value), default=None)


def normalize_status(value):
    """
    Turn an EPP status into lowercase words.

    Examples:
        >>> normalize_status("clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited")
        'client delete prohibited'
    """
    match = _STATUS_CODE_REGEX.match(str(value).strip())
    if not match:
        return None
    return _CAMEL_REGEX.sub(" ", match.group(1)).lower()


def _clean(value):
    value = next(iter(_as_list(value)), None)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def normalize_whois(domain, entry, text=""):
    """
    Convert a parsed python-whois entry into DOMAIN_REGISTRATION event data.

    Placeholder registrant values are dropped and set registrant_redacted=True.
    Redaction is per-field, so e.g. a redacted name can still come with a real organization.
    """
    record = {"host": domain, "registrant_redacted": False}

    registrar = _clean(entry.get("registrar"))
    if registrar:
        record["registrar"] = registrar
    iana_id = _IANA_ID_REGEX.search(text or "")
    if iana_id:
        record["registrar_iana_id"] = iana_id.group(1)

    raw_org = _clean(entry.get("org")) or _clean(entry.get("registrant_organization"))
    raw_name = _clean(entry.get("name")) or _clean(entry.get("registrant_name"))
    email_match = _REGISTRANT_EMAIL_REGEX.search(text or "")
    raw_email = email_match.group(1) if email_match else None
    raw_country = _clean(entry.get("country"))
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
    # registrant email is often a web form link rather than an address, which means it's withheld
    if not email_match and re.search(r"^\s*Registrant Email:\s*\S", text or "", re.I | re.M):
        record["registrant_redacted"] = True
    # if the registrant is a privacy service, the address (and therefore country) is the privacy service's too
    if is_proxy_service(raw_org) or (not record.get("registrant_org") and is_proxy_service(raw_name)):
        record.pop("registrant_country", None)
    if record.get("registrant_email"):
        record["registrant_email"] = record["registrant_email"].lower()
    country = record.get("registrant_country")
    if country and len(country) == 2:
        record["registrant_country"] = country.upper()

    for field, key, pick in (
        ("created", "creation_date", _first_date),
        ("updated", "updated_date", _latest_date),
        ("expires", "expiration_date", _first_date),
    ):
        date = pick(entry.get(key))
        if date:
            record[field] = date

    nameservers = [str(ns).strip().strip(".").lower() for ns in _as_list(entry.get("name_servers"))]
    record["nameservers"] = sorted({ns for ns in nameservers if ns})
    statuses = (normalize_status(s) for s in _as_list(entry.get("status")))
    record["status"] = sorted({s for s in statuses if s})

    whois_server = _clean(entry.get("whois_server"))
    if whois_server:
        record["whois_server"] = whois_server.lower()
    return record


def parse_whois(domain, text):
    """
    Parse raw WHOIS text for a domain into DOMAIN_REGISTRATION event data, without network access.

    Returns None if the text has no registration data.
    """
    try:
        entry = WhoisEntry.load(domain, text)
    except PywhoisError:
        return None
    if not any(entry.get(k) for k in ("registrar", "creation_date", "expiration_date", "name_servers")):
        return None
    return normalize_whois(domain, entry, text)


class WhoisHelper:
    """
    WHOIS domain registration lookups, accessible via `self.helpers.whois`.

    Lookups run python-whois in a thread, are cached per domain for the lifetime of the scan, and are
    limited by a semaphore. A failed lookup returns None; it never raises into the caller.

    Examples:
        >>> record = await self.helpers.whois.lookup("github.com")
        >>> record["registrar"]
        'MarkMonitor, Inc.'
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._cache = {}

    async def query(self, domain, **whois_kwargs):
        """Return raw WHOIS text for a domain, or None on failure."""
        try:
            entry = await self.parent_helper.run_in_executor_io(
                python_whois.whois, domain, quiet=True, inc_raw=True, **whois_kwargs
            )
        except Exception as e:
            log.debug(f"WHOIS lookup for {domain} failed: {e}")
            return None
        return entry.get("raw") or getattr(entry, "text", None)

    async def lookup(self, domain, include_raw=False, **whois_kwargs):
        """
        Look up and parse WHOIS registration data for a registrable domain. Returns None on failure.

        Extra keyword arguments (e.g. timeout) go to python-whois.
        """
        domain = domain.lower()
        if domain not in self._cache:
            self._cache[domain] = asyncio.ensure_future(self.query(domain, **whois_kwargs))
        text = await self._cache[domain]
        if not text:
            return None
        record = parse_whois(domain, text)
        if record and include_raw:
            record["raw"] = text
        return record
