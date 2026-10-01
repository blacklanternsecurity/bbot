"""
RDAP (Registration Data Access Protocol) lookups for domain registration data.

RDAP is the structured, JSON-based successor to port-43 WHOIS (RFC 7480-7484, RFC 9082/9083).
The IANA bootstrap registry (RFC 9224) maps TLDs to the RDAP server of the registry that runs them.

Everything that doesn't need network access (bootstrap matching, jCard parsing, redaction detection,
date normalization, merging registry + registrar responses) lives in module-level pure functions,
so it can be reused without a scan or a ConfigAwareHelper. `RDAPHelper` is a thin stateful layer
on top that handles HTTP, the bootstrap cache, and per-server rate limiting / circuit breaking.
"""

import re
import json
import time
import random
import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from .misc import parse_retry_after

log = logging.getLogger("bbot.core.helpers.rdap")


RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_MEDIA_TYPE = "application/rdap+json"

# eventAction -> normalized field
_EVENT_FIELDS = {
    "registration": "created",
    "last changed": "updated",
    "expiration": "expires",
    # when the RDAP server's data was last refreshed (not a change to the registration itself)
    "last update of rdap database": "rdap_updated",
}
# used for "expires" only when the server doesn't provide a plain "expiration" event
_FALLBACK_EXPIRATION_ACTION = "registrar expiration"

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
# values registrars/registries put in place of real registrant data
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
# fractional seconds of any length (RDAP servers send 0-9 digits)
_FRACTION_REGEX = re.compile(r"(\.\d+)")
# a UTC offset without a colon (e.g. "+0000"), which RFC 3339 forbids but some servers send
_COMPACT_OFFSET_REGEX = re.compile(r"(T[\d:.]+[+-]\d{2})(\d{2})$")


def bootstrap_services(bootstrap):
    """
    Convert an IANA RDAP DNS bootstrap document (RFC 9224) into a mapping of suffix -> list of base URLs.

    Base URLs are ordered so that https comes first.

    Examples:
        >>> bootstrap_services({"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]})
        {'com': ['https://rdap.verisign.com/com/v1/'], 'net': ['https://rdap.verisign.com/com/v1/']}
    """
    services = {}
    for service in bootstrap.get("services", []) or []:
        try:
            suffixes, urls = service[0], service[1]
        except (IndexError, KeyError, TypeError):
            continue
        urls = [u for u in urls if isinstance(u, str) and u.lower().startswith(("https://", "http://"))]
        if not urls:
            continue
        urls = sorted(urls, key=lambda u: not u.lower().startswith("https://"))
        for suffix in suffixes:
            if isinstance(suffix, str) and suffix:
                services[suffix.lower().strip(".")] = urls
    return services


def bootstrap_match(services, domain):
    """
    Return the RDAP base URLs for a domain using longest-suffix matching against bootstrap services.

    Returns an empty list if no bootstrap entry covers the domain.

    Examples:
        >>> bootstrap_match({"uk": ["https://rdap.nominet.uk/uk/"]}, "bbc.co.uk")
        ['https://rdap.nominet.uk/uk/']
    """
    labels = domain.lower().strip(".").split(".")
    # start at 1: the domain itself is never a bootstrap entry, only its suffixes are
    for i in range(1, len(labels)):
        urls = services.get(".".join(labels[i:]), [])
        if urls:
            return urls
    return []


def domain_query_url(base_url, domain):
    """
    Build an RDAP domain query URL (RFC 9082 section 3.1.3) from a bootstrap base URL.

    Examples:
        >>> domain_query_url("https://rdap.verisign.com/com/v1/", "github.com")
        'https://rdap.verisign.com/com/v1/domain/github.com'
    """
    return f"{base_url.rstrip('/')}/domain/{domain}"


def parse_rdap_date(value):
    """
    Normalize an RDAP timestamp (RFC 3339) to a UTC ISO-8601 string like "2007-10-09T18:20:50Z".

    Handles "Z" and numeric offsets, any number of fraction digits, and naive timestamps (assumed UTC).
    Returns None if the value can't be parsed.

    Examples:
        >>> parse_rdap_date("2026-08-12T08:47:19.41Z")
        '2026-08-12T08:47:19Z'
        >>> parse_rdap_date("2028-10-09T18:20:50.000+00:00")
        '2028-10-09T18:20:50Z'
    """
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value[-1] in "zZ":
        value = value[:-1] + "+00:00"
    # datetime.fromisoformat() on python 3.10 only accepts 3 or 6 fraction digits, and only "+HH:MM" offsets
    value = _FRACTION_REGEX.sub(lambda m: m.group(1)[:7].ljust(7, "0"), value, count=1)
    value = _COMPACT_OFFSET_REGEX.sub(r"\1:\2", value)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    if "@" in value:
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


def parse_vcard(vcard_array):
    """
    Extract the useful properties from a jCard (RFC 7095) "vcardArray".

    Returns a dict with keys fn, org, email, country (each a string or None).
    Values are returned exactly as the server sent them; placeholder detection happens in `parse_registrant()`.

    Examples:
        >>> parse_vcard(["vcard", [["version", {}, "text", "4.0"], ["org", {"type": "work"}, "text", "GitHub, Inc."], ["adr", {"cc": "US"}, "text", ["", "", "", "", "", "", ""]]]])
        {'fn': None, 'org': 'GitHub, Inc.', 'email': None, 'country': 'US'}
    """
    result = {"fn": None, "org": None, "email": None, "country": None}
    try:
        properties = vcard_array[1]
    except (IndexError, KeyError, TypeError):
        return result
    for prop in properties:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name, params, _value_type, value = prop[0], prop[1], prop[2], prop[3]
        name = str(name).lower()
        params = params if isinstance(params, dict) else {}
        if name in ("fn", "email") and result[name] is None:
            if isinstance(value, str):
                result[name] = value.strip()
        elif name == "org" and result["org"] is None:
            # org may be a list of organizational units, the first is the organization name
            if isinstance(value, list):
                value = next((v for v in value if isinstance(v, str) and v.strip()), "")
            if isinstance(value, str):
                result["org"] = value.strip()
        elif name == "adr" and result["country"] is None:
            country = params.get("cc", "")
            if not (isinstance(country, str) and country.strip()) and isinstance(value, list) and len(value) >= 7:
                country = value[6]
            if isinstance(country, str) and country.strip():
                result["country"] = country.strip()
    return result


def find_entity(entities, role, nested=True):
    """
    Find the first entity with a given role, optionally searching one level of nested entities.

    Some ccTLD registries nest the registrant inside the registrar entity.
    """
    entities = [e for e in (entities or []) if isinstance(e, dict)]
    for entity in entities:
        if role in (entity.get("roles", []) or []):
            return entity
    if nested:
        for entity in entities:
            found = find_entity(entity.get("entities", []), role, nested=False)
            if found is not None:
                return found
    return None


def _registrant_redaction_declared(rdap_json):
    """RFC 9537: check for "redacted" members describing registrant fields."""
    if "redacted" not in (rdap_json.get("rdapConformance", []) or []):
        return False
    for item in rdap_json.get("redacted", []) or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name", {}) or {}
        if not isinstance(name, dict):
            continue
        label = name.get("type", "") or name.get("description", "") or ""
        if isinstance(label, str) and label.lower().startswith("registrant"):
            return True
    return False


def _entity_redaction_remarked(entity):
    """Check an entity's remarks for redaction notices (e.g. "REDACTED FOR PRIVACY")."""
    for remark in entity.get("remarks", []) or []:
        if not isinstance(remark, dict):
            continue
        title = str(remark.get("title", "") or "").lower()
        remark_type = str(remark.get("type", "") or "").lower()
        if "redacted" in title or remark_type == "object redacted due to authorization":
            return True
    return False


def parse_registrant(rdap_json):
    """
    Extract registrant fields from an RDAP domain response, with per-field redaction handling.

    Returns a dict with registrant_org, registrant_name, registrant_email, registrant_country, and
    registrant_redacted. Placeholder values are replaced with None and set registrant_redacted=True.
    Redaction is per-field, so e.g. a redacted name can still come with a real organization.
    """
    result = {
        "registrant_org": None,
        "registrant_name": None,
        "registrant_email": None,
        "registrant_country": None,
        "registrant_redacted": _registrant_redaction_declared(rdap_json),
    }
    entity = find_entity(rdap_json.get("entities", []), "registrant")
    if entity is None:
        return result
    if _entity_redaction_remarked(entity):
        result["registrant_redacted"] = True
    vcard = parse_vcard(entity.get("vcardArray", []))
    for vcard_key, field in (
        ("org", "registrant_org"),
        ("fn", "registrant_name"),
        ("email", "registrant_email"),
        ("country", "registrant_country"),
    ):
        value = vcard[vcard_key]
        if not value:
            continue
        if is_placeholder(value):
            result["registrant_redacted"] = True
            continue
        result[field] = value
    # if the registrant is a privacy service, the address (and therefore country) is the privacy service's too
    if is_proxy_service(vcard["org"]) or (not result["registrant_org"] and is_proxy_service(vcard["fn"])):
        result["registrant_country"] = None
    if result["registrant_email"]:
        result["registrant_email"] = result["registrant_email"].lower()
    if result["registrant_country"] and len(result["registrant_country"]) == 2:
        result["registrant_country"] = result["registrant_country"].upper()
    return result


def parse_registrar(rdap_json):
    """
    Extract the registrar name and IANA registrar ID from an RDAP domain response.
    """
    result = {"registrar": None, "registrar_iana_id": None}
    entity = find_entity(rdap_json.get("entities", []), "registrar", nested=False)
    if entity is None:
        return result
    vcard = parse_vcard(entity.get("vcardArray", []))
    result["registrar"] = vcard["fn"] or vcard["org"] or None
    for public_id in entity.get("publicIds", []) or []:
        if isinstance(public_id, dict) and str(public_id.get("type", "")).lower() == "iana registrar id":
            identifier = public_id.get("identifier", None)
            if identifier not in (None, ""):
                result["registrar_iana_id"] = str(identifier)
                break
    return result


def parse_events(rdap_json):
    """
    Extract created/updated/expires/rdap_updated dates from an RDAP domain response's events.
    """
    result = {"created": None, "updated": None, "expires": None, "rdap_updated": None}
    fallback_expiration = None
    for event in rdap_json.get("events", []) or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        date = parse_rdap_date(event.get("eventDate", None))
        if date is None:
            continue
        field = _EVENT_FIELDS.get(action, None)
        if field is not None and result[field] is None:
            result[field] = date
        elif action == _FALLBACK_EXPIRATION_ACTION and fallback_expiration is None:
            fallback_expiration = date
    if result["expires"] is None:
        result["expires"] = fallback_expiration
    return result


def parse_nameservers(rdap_json):
    """
    Extract a sorted, deduplicated, lowercase list of nameserver hostnames.
    """
    nameservers = set()
    for ns in rdap_json.get("nameservers", []) or []:
        if isinstance(ns, dict):
            name = ns.get("ldhName", "")
            if isinstance(name, str) and name.strip(". "):
                nameservers.add(name.strip().strip(".").lower())
    return sorted(nameservers)


def registrar_link(rdap_json):
    """
    Return the registrar's RDAP URL for this domain (the top-level "related" link), or None.

    Thin registries (e.g. .com, .net) and most gTLD registries since the RDAP response profile
    no longer carry registrant data; it lives on the registrar's RDAP server.
    """
    for link in rdap_json.get("links", []) or []:
        if not isinstance(link, dict):
            continue
        if str(link.get("rel", "")).lower() != "related":
            continue
        link_type = str(link.get("type", RDAP_MEDIA_TYPE) or RDAP_MEDIA_TYPE).lower()
        if not link_type.startswith(RDAP_MEDIA_TYPE):
            continue
        href = link.get("href", "")
        if isinstance(href, str) and href.lower().startswith(("https://", "http://")):
            return href
    return None


def normalize_rdap(rdap_json, rdap_server=None):
    """
    Normalize a single RDAP domain response into BBOT's stable registration dict.

    Keys: domain, registrar, registrar_iana_id, registrant_org, registrant_name, registrant_email,
    registrant_country, registrant_redacted, created, updated, expires, rdap_updated, nameservers, status, rdap_server.
    """
    domain = rdap_json.get("ldhName", "") or rdap_json.get("unicodeName", "") or ""
    status = [s for s in (rdap_json.get("status", []) or []) if isinstance(s, str) and s]
    record = {"domain": str(domain).strip(".").lower() or None}
    record.update(parse_registrar(rdap_json))
    record.update(parse_registrant(rdap_json))
    record.update(parse_events(rdap_json))
    record["nameservers"] = parse_nameservers(rdap_json)
    record["status"] = status
    record["rdap_server"] = rdap_server
    return record


_REGISTRANT_FIELDS = ("registrant_org", "registrant_name", "registrant_email", "registrant_country")


def merge_records(registry_record, registrar_record):
    """
    Merge a normalized registry record with the normalized record from the registrar's RDAP server.

    The registry is authoritative for registrar, dates, nameservers, and status; the registrar is
    authoritative for registrant data. Any remaining gaps are filled from the other record.
    """
    merged = dict(registry_record)
    registrar_has_registrant = any(registrar_record.get(f) for f in _REGISTRANT_FIELDS) or registrar_record.get(
        "registrant_redacted", False
    )
    if registrar_has_registrant:
        for field in _REGISTRANT_FIELDS:
            merged[field] = registrar_record.get(field) or registry_record.get(field)
        # the registrant data came from the registrar, so its redaction flag is the one that describes it
        merged["registrant_redacted"] = bool(registrar_record.get("registrant_redacted", False))
    else:
        merged["registrant_redacted"] = bool(registry_record.get("registrant_redacted", False))
    for field, value in registrar_record.items():
        if field in _REGISTRANT_FIELDS or field in ("registrant_redacted", "rdap_server"):
            continue
        if not merged.get(field) and value:
            merged[field] = value
    merged["registrar_rdap_server"] = registrar_record.get("rdap_server", None)
    return merged


class RDAPServerState:
    """
    Rate-limiting and circuit-breaker state for a single RDAP server (keyed by netloc).
    """

    def __init__(self, netloc, concurrency, interval):
        self.netloc = netloc
        self.interval = interval
        self.semaphore = asyncio.Semaphore(max(1, int(concurrency)))
        self._interval_lock = asyncio.Lock()
        self.next_allowed = 0.0
        self.consecutive_failures = 0
        self.rate_limited = 0
        self.tripped = False
        self.tripped_at = None

    def cooldown_remaining(self):
        """Seconds until the next request to this server is allowed."""
        return max(0.0, self.next_allowed - time.monotonic())

    async def wait_turn(self, max_wait=None):
        """
        Wait until this server's minimum interval (and any 429 cooldown) has elapsed.

        Returns False without waiting if the remaining delay exceeds `max_wait` (e.g. a long 429 cooldown),
        so the caller can give up instead of tying up a worker. A cooldown set by another request while
        we're waiting is honored, not overwritten.
        """
        async with self._interval_lock:
            while True:
                delay = self.cooldown_remaining()
                if delay <= 0:
                    break
                if max_wait is not None and delay > max_wait:
                    return False
                await asyncio.sleep(delay)
            self.next_allowed = max(self.next_allowed, time.monotonic() + self.interval)
            return True

    def cool_down(self, seconds):
        self.next_allowed = max(self.next_allowed, time.monotonic() + seconds)

    def trip(self):
        self.tripped = True
        self.tripped_at = time.monotonic()

    def reset(self):
        """Close the circuit breaker and forget past failures."""
        self.tripped = False
        self.tripped_at = None
        self.consecutive_failures = 0

    def is_tripped(self, reset_seconds=None):
        """
        Return True if the circuit breaker is open.

        After `reset_seconds`, the breaker goes half-open: one request is let through, and a single
        further failure trips it again (see `RDAPHelper._record_failure()`).
        """
        if not self.tripped:
            return False
        if reset_seconds is not None and time.monotonic() - self.tripped_at >= reset_seconds:
            self.tripped = False
            self.tripped_at = None
            return False
        return True


class RDAPHelper:
    """
    RDAP domain registration lookups, accessible via `self.helpers.rdap`.

    Rate limits and failures are tracked per RDAP server, so a slow or broken server never stalls
    lookups against other servers. A failed lookup returns None; it never raises into the caller.

    Waiting is bounded: a lookup never sleeps longer than `max_retry_after` for a server. If a server
    asks for a longer cooldown (via Retry-After), lookups against it fail fast until the cooldown is over.

    Examples:
        >>> record = await self.helpers.rdap.lookup("github.com")
        >>> record["registrar"]
        'MarkMonitor Inc.'
    """

    bootstrap_url = RDAP_BOOTSTRAP_URL
    bootstrap_cache_hrs = 24
    # how long to wait before retrying a failed bootstrap download
    bootstrap_retry_seconds = 300
    bootstrap_timeout = 60

    _settings = (
        "timeout",
        "server_concurrency",
        "server_interval",
        "max_retries",
        "default_retry_after",
        "max_retry_after",
        "failure_threshold",
        "circuit_reset_seconds",
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        web_config = getattr(parent_helper, "web_config", {}) or {}
        self.timeout = 10
        self.server_concurrency = 1
        self.server_interval = 1.0
        self.max_retries = 2
        self.default_retry_after = float(web_config.get("429_sleep_interval", 30))
        self.max_retry_after = float(web_config.get("429_max_sleep_interval", 60))
        self.failure_threshold = 5
        # how long a tripped server is skipped before it gets another chance
        self.circuit_reset_seconds = 600.0
        self._servers = {}
        self._services = None
        self._services_loaded_at = 0.0
        self._bootstrap_failed_at = None
        self._bootstrap_lock = asyncio.Lock()

    def configure(self, **kwargs):
        """
        Override lookup settings. Accepted keys: timeout, server_concurrency, server_interval,
        max_retries, default_retry_after, max_retry_after, failure_threshold, circuit_reset_seconds.

        Concurrency and interval changes only apply to servers that haven't been contacted yet.
        """
        for key, value in kwargs.items():
            if value is None:
                continue
            if key not in self._settings:
                raise ValueError(f"Unknown RDAP setting: {key}")
            setattr(self, key, value)

    def server_state(self, url):
        netloc = urlparse(url).netloc.lower()
        state = self._servers.get(netloc, None)
        if state is None:
            state = RDAPServerState(netloc, self.server_concurrency, self.server_interval)
            self._servers[netloc] = state
        return state

    def _services_fresh(self):
        return self._services is not None and (
            time.monotonic() - self._services_loaded_at < self.bootstrap_cache_hrs * 3600
        )

    def _bootstrap_backing_off(self):
        return (
            self._bootstrap_failed_at is not None
            and time.monotonic() - self._bootstrap_failed_at < self.bootstrap_retry_seconds
        )

    async def bootstrap(self):
        """
        Return the parsed IANA bootstrap as a mapping of suffix -> base URLs (empty dict on failure).

        The raw file is cached on disk for `bootstrap_cache_hrs`, and the parsed result is memoized.
        After a failed download, no new attempt is made for `bootstrap_retry_seconds`.
        """
        if self._services_fresh():
            return self._services
        if self._bootstrap_backing_off():
            return self._services or {}
        async with self._bootstrap_lock:
            # another task may have loaded it (or failed to) while we waited for the lock
            if self._services_fresh():
                return self._services
            if self._bootstrap_backing_off():
                return self._services or {}
            services = None
            try:
                filename = await self.parent_helper.download(
                    self.bootstrap_url, cache_hrs=self.bootstrap_cache_hrs, warn=False, timeout=self.bootstrap_timeout
                )
                if filename is not None:
                    with open(filename, encoding="utf-8") as f:
                        services = bootstrap_services(json.load(f))
            except Exception as e:
                log.debug(f"Error loading RDAP bootstrap from {self.bootstrap_url}: {e}")
            if services:
                self._services = services
                self._services_loaded_at = time.monotonic()
                self._bootstrap_failed_at = None
            else:
                log.warning(f"Failed to load RDAP bootstrap from {self.bootstrap_url}")
                # discard a bad cached copy so the next attempt re-downloads it
                try:
                    self.parent_helper.cache_filename(self.bootstrap_url).unlink(missing_ok=True)
                except Exception:
                    pass
                self._bootstrap_failed_at = time.monotonic()
        return self._services or {}

    async def base_urls(self, domain):
        """Return the RDAP base URLs responsible for a domain (empty list if not in the bootstrap)."""
        return bootstrap_match(await self.bootstrap(), domain)

    async def query(self, url):
        """
        Fetch and decode an RDAP JSON document, honoring per-server limits.

        Returns the decoded JSON dict, or None if the object wasn't found or the request failed.
        Rate limiting (HTTP 429) is not counted as a server failure: the server is alive, just busy.
        """
        state = self.server_state(url)
        attempts = 0
        while True:
            if state.is_tripped(self.circuit_reset_seconds):
                log.debug(f"Skipping RDAP request to {url}: {state.netloc} has failed too many times")
                return None
            async with state.semaphore:
                # the regular interval is always waited out; only a 429 cooldown beyond max_retry_after is skipped
                if not await state.wait_turn(max_wait=self.max_retry_after + state.interval):
                    log.debug(
                        f"Skipping RDAP request to {url}: {state.netloc} is cooling down for another "
                        f"{state.cooldown_remaining():.0f}s"
                    )
                    return None
                if state.is_tripped(self.circuit_reset_seconds):
                    return None
                r = await self.parent_helper.request(
                    url,
                    headers={"Accept": RDAP_MEDIA_TYPE},
                    timeout=self.timeout,
                    follow_redirects=True,
                    max_redirects=3,
                    ssl_verify=self.parent_helper.web_config.get("ssl_verify_infrastructure", True),
                )
            status_code = getattr(r, "status_code", 0)
            if r is None or status_code >= 500:
                self._record_failure(state, f"status code {status_code}" if r is not None else "request failed", url)
                return None
            if status_code == 429:
                state.rate_limited += 1
                attempts += 1
                delay = parse_retry_after(r.headers.get("Retry-After", None))
                if delay is not None and delay > self.max_retry_after:
                    # retrying before the server's deadline would only get us rate limited again,
                    # so honor the full cooldown and skip this server's lookups until then
                    log.info(f"RDAP server {state.netloc} rate limited us for {delay:.0f}s, skipping it until then")
                    state.cool_down(delay)
                    return None
                if delay is None:
                    # no retry-after: exponential backoff with jitter
                    delay = self.default_retry_after * (2 ** (attempts - 1)) * random.uniform(0.5, 1.0)
                    delay = min(delay, self.max_retry_after)
                state.cool_down(delay)
                if attempts > self.max_retries:
                    log.debug(f"Giving up on {url} after being rate limited {attempts} times")
                    return None
                log.info(f"RDAP server {state.netloc} rate limited us, sleeping {delay:.1f}s ({url})")
                continue
            # any other non-failure response means the server is alive
            state.consecutive_failures = 0
            if status_code == 404:
                log.debug(f"RDAP object not found: {url}")
                return None
            if status_code != 200:
                log.debug(f"Unexpected RDAP status code {status_code} from {url}")
                return None
            try:
                j = r.json()
            except Exception:
                self._record_failure(state, "invalid JSON", url)
                return None
            if not isinstance(j, dict):
                self._record_failure(state, "invalid RDAP response", url)
                return None
            return j

    def _record_failure(self, state, reason, url):
        state.consecutive_failures += 1
        log.debug(f"RDAP request to {url} failed ({reason}), {state.consecutive_failures} consecutive failures")
        if not state.tripped and state.consecutive_failures >= self.failure_threshold:
            state.trip()
            log.warning(
                f"RDAP server {state.netloc} failed {state.consecutive_failures} times in a row, "
                f"skipping it for {self.circuit_reset_seconds:.0f}s"
            )

    async def lookup(self, domain, follow_registrar=True, include_raw=False):
        """
        Look up a registrable domain's registration data via RDAP.

        Args:
            domain (str): Registrable domain, e.g. "evilcorp.co.uk" (not a subdomain or a bare TLD).
            follow_registrar (bool): Also query the registrar's RDAP server (via the registry's "related" link),
                which is where registrant data lives for most gTLDs.
            include_raw (bool): Include the raw RDAP responses under the "raw" key.

        Returns:
            dict or None: Normalized registration data (see `normalize_rdap()`), or None if the domain isn't
                covered by the bootstrap, wasn't found, or the lookup failed.
        """
        try:
            return await self._lookup(domain, follow_registrar=follow_registrar, include_raw=include_raw)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning(f"RDAP lookup for {domain} failed: {e}")
            log.debug(f"{e}", exc_info=True)
            return None

    async def _lookup(self, domain, follow_registrar, include_raw):
        domain = str(domain).strip().strip(".").lower()
        if not domain or "." not in domain:
            return None
        base_urls = await self.base_urls(domain)
        if not base_urls:
            log.debug(f"No RDAP server in the IANA bootstrap for {domain}")
            return None
        url = domain_query_url(base_urls[0], domain)
        registry_json = await self.query(url)
        if registry_json is None:
            return None
        record = normalize_rdap(registry_json, rdap_server=url)
        record["domain"] = record["domain"] or domain
        raw = {"registry": registry_json}
        if follow_registrar:
            related_url = registrar_link(registry_json)
            if related_url and related_url.rstrip("/").lower() != url.rstrip("/").lower():
                registrar_json = await self.query(related_url)
                if registrar_json is not None:
                    record = merge_records(record, normalize_rdap(registrar_json, rdap_server=related_url))
                    raw["registrar"] = registrar_json
        if include_raw:
            record["raw"] = raw
        return record
