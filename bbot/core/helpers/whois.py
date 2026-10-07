"""
WHOIS lookups for domain registration data, backed by python-whois.

Parsing lives in module-level functions so it can be used on raw WHOIS text without a scan.
"""

import re
import time
import logging

import whois as python_whois
from whois.parser import WhoisEntry
from whois.exceptions import PywhoisError

from .registration import (
    REGISTRANT_FIELDS,
    apply_registrant,
    as_list,
    clean,
    is_placeholder,  # noqa: F401
    is_proxy_service,  # noqa: F401
    parse_registration_date,
)

log = logging.getLogger("bbot.core.helpers.whois")


# EPP status codes come with a trailing ICANN link, e.g. "clientDeleteProhibited https://icann.org/epp#..."
_STATUS_CODE_REGEX = re.compile(r"^([A-Za-z]+)")
_CAMEL_REGEX = re.compile(r"(?<=[a-z])(?=[A-Z])")
_IANA_ID_REGEX = re.compile(r"^\s*Registrar IANA ID:\s*(\d+)", re.I | re.M)
_REGISTRANT_EMAIL_REGEX = re.compile(r"^\s*Registrant Email:\s*(\S.*?)\s*$", re.I | re.M)

# a response without any of these isn't a registration record
_REGISTRATION_FIELDS = ("registrar", "creation_date", "expiration_date", "name_servers")


def _dates(value):
    return [d for d in map(parse_registration_date, as_list(value)) if d]


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


def has_registration_data(entry):
    """Return True if a parsed python-whois entry carries actual registration data."""
    return any(entry.get(k) for k in _REGISTRATION_FIELDS)


def normalize_whois(entry, text=""):
    """
    Convert a parsed python-whois entry into a registration record.

    Placeholder registrant values are dropped and set registrant_redacted=True.
    Redaction is per-field, so e.g. a redacted name can still come with a real organization.
    """
    record = {"source": "whois", "registrant_redacted": False}

    registrar = clean(entry.get("registrar"))
    if registrar:
        record["registrar"] = registrar
    iana_id = _IANA_ID_REGEX.search(text or "")
    if iana_id:
        record["registrar_iana_id"] = iana_id.group(1)

    raw_org = clean(entry.get("org")) or clean(entry.get("registrant_organization"))
    raw_name = clean(entry.get("name")) or clean(entry.get("registrant_name"))
    email_match = _REGISTRANT_EMAIL_REGEX.search(text or "")
    raw_email = email_match.group(1) if email_match else None
    # registrant email is often a web form link rather than an address, which means it's withheld
    if raw_email and "@" not in raw_email:
        raw_email = None
        record["registrant_redacted"] = True
    apply_registrant(record, raw_org, raw_name, raw_email, clean(entry.get("country")))

    for field, key, pick in (
        ("created", "creation_date", _first_date),
        ("updated", "updated_date", _latest_date),
        ("expires", "expiration_date", _first_date),
    ):
        date = pick(entry.get(key))
        if date:
            record[field] = date

    nameservers = [str(ns).strip().strip(".").lower() for ns in as_list(entry.get("name_servers"))]
    record["nameservers"] = sorted({ns for ns in nameservers if ns})
    statuses = (normalize_status(s) for s in as_list(entry.get("status")))
    record["status"] = sorted({s for s in statuses if s})

    whois_server = clean(entry.get("whois_server"))
    if whois_server:
        record["whois_server"] = whois_server.lower()
    return record


def parse_whois(domain, text):
    """
    Parse raw WHOIS text for a domain into a registration record, without network access.

    Returns None if the text has no registration data.
    """
    try:
        entry = WhoisEntry.load(domain, text)
    except PywhoisError:
        return None
    if not has_registration_data(entry):
        return None
    return normalize_whois(entry, text)


def _shared_cache():
    """
    baddns keeps a process-global WHOIS cache on its WhoisManager, keyed by registrable domain, shaped
    {domain: {"type": "response"|"error", "data": WhoisEntry|str}}. Reading and writing it directly means
    a domain is queried once no matter which of us gets there first.

    baddns is optional: it is installed on demand with the baddns module, and it owns the shape of that
    dict. Anything at all going wrong here falls back to a private cache, so WHOIS never depends on it.
    """
    try:
        from baddns.lib.whoismanager import WhoisManager

        return WhoisManager._cache
    except Exception as e:
        log.debug(f"baddns is unavailable ({e}); WHOIS lookups will use a private cache")
        return {}


class WhoisHelper:
    """
    WHOIS domain registration lookups, accessible via `self.helpers.whois`.

    Lookups run python-whois in a thread and are cached per domain, shared with baddns.
    A failed lookup returns None; it never raises.

    Examples:
        >>> record = await self.helpers.whois.lookup("github.com")
        >>> record["registrar"]
        'MarkMonitor, Inc.'
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._cache = None

    @property
    def cache(self):
        if self._cache is None:
            self._cache = _shared_cache()
        return self._cache

    def clear_cache(self):
        self.cache.clear()

    async def query(self, domain, **whois_kwargs):
        """Return the python-whois entry for a domain, or None on failure."""
        cached = self.cache.get(domain)
        # baddns owns the cache's shape; an entry we don't recognize just means we query again
        if isinstance(cached, dict) and "type" in cached:
            return cached["data"] if cached["type"] == "response" else None
        # each query blocks the intercept chain, so log how long it took to make a stall diagnosable
        start = time.time()
        try:
            entry = await self.parent_helper.run_in_executor_io(python_whois.whois, domain, quiet=True, **whois_kwargs)
        except Exception as e:
            log.debug(f"WHOIS for {domain} failed after {time.time() - start:.1f}s: {e}")
            self.cache[domain] = {"type": "error", "data": str(e)}
            return None
        log.debug(f"WHOIS for {domain} took {time.time() - start:.1f}s")
        self.cache[domain] = {"type": "response", "data": entry}
        return entry

    async def lookup(self, domain, include_raw=False, rdap_fallback=True, **whois_kwargs):
        """
        Look up and parse registration data for a registrable domain. Returns None on failure.

        WHOIS is tried first, because its cache is shared with baddns. Registries that don't serve
        port 43 (e.g. Nominet for .uk) answer over RDAP instead, so a failure falls back to it.

        Extra keyword arguments (e.g. timeout) go to python-whois.
        """
        domain = domain.lower()
        entry = await self.query(domain, **whois_kwargs)
        if entry is not None and has_registration_data(entry):
            text = getattr(entry, "text", "") or ""
            record = normalize_whois(entry, text)
            if include_raw:
                record["raw"] = text
            return record
        if not rdap_fallback:
            return None
        rdap_record = await self.parent_helper.rdap.lookup(domain, include_raw=include_raw)
        if not rdap_record:
            return None
        # reshape RDAP's record to match normalize_whois(): same keys, empty ones left out
        record = {"source": "rdap", "registrant_redacted": bool(rdap_record.get("registrant_redacted"))}
        fields = ("registrar", "registrar_iana_id", *REGISTRANT_FIELDS, "created", "updated", "expires", "rdap_server")
        for field in fields:
            value = rdap_record.get(field)
            if value:
                record[field] = value
        record["nameservers"] = rdap_record.get("nameservers") or []
        record["status"] = rdap_record.get("status") or []
        if include_raw and rdap_record.get("raw"):
            record["raw"] = rdap_record["raw"]
        return record
