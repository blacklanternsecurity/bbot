from ..bbot_fixtures import *  # noqa: F401,F403
import re
import time
import asyncio
import pytest

from bbot.test.mock_blasthttp import MockResponse
from bbot.test.rdap_samples import rdap_sample
from bbot.core.helpers.rdap import (
    RDAPHelper,
    RDAPServerState,
    RDAP_BOOTSTRAP_URL,
    bootstrap_match,
    bootstrap_services,
    is_placeholder,
    is_proxy_service,
    merge_records,
    normalize_rdap,
    parse_rdap_date,
    parse_vcard,
    registrar_link,
)

VERISIGN_GITHUB = "https://rdap.verisign.com/com/v1/domain/github.com"
MARKMONITOR_GITHUB = "https://rdap.markmonitor.com/rdap/domain/GITHUB.COM"
PIR_WIKIPEDIA = "https://rdap.publicinterestregistry.org/rdap/domain/wikipedia.org"
MARKMONITOR_WIKIPEDIA = "https://rdap.markmonitor.com/rdap/domain/wikipedia.org"
NOMINET_BBC = "https://rdap.nominet.uk/uk/domain/bbc.co.uk"

GITHUB_NAMESERVERS = [
    "dns1.p08.nsone.net",
    "dns2.p08.nsone.net",
    "dns3.p08.nsone.net",
    "dns4.p08.nsone.net",
    "ns-1283.awsdns-32.org",
    "ns-1707.awsdns-21.co.uk",
    "ns-421.awsdns-52.com",
    "ns-520.awsdns-01.net",
]


@pytest.fixture
def rdap(helpers, blasthttp_mock):
    """A fresh RDAPHelper (clean per-server state) with a mocked IANA bootstrap"""
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)
    blasthttp_mock.add_response(url=RDAP_BOOTSTRAP_URL, json=rdap_sample("iana_dns_bootstrap_trimmed"))
    rdap_helper = RDAPHelper(helpers)
    rdap_helper.configure(server_interval=0, max_retry_after=0.1, default_retry_after=0.1)
    yield rdap_helper
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)


def count_requests(blasthttp_mock, url, *responses):
    """Register a callback that returns `responses` in order (repeating the last one) and counts requests."""
    calls = []

    def callback(request):
        response = responses[min(len(calls), len(responses) - 1)]
        calls.append(request.url)
        return response

    blasthttp_mock.add_callback(callback, url=url)
    return calls


def time_requests(blasthttp_mock, url, response, delay=0.0):
    """Register an async callback that records (url, start, end) for each request, taking `delay` seconds each."""
    calls = []

    async def callback(request):
        start = time.monotonic()
        await asyncio.sleep(delay)
        calls.append((request.url, start, time.monotonic()))
        return response

    blasthttp_mock.add_callback(callback, url=url)
    return calls


def test_rdap_parse_dates():
    assert parse_rdap_date("2007-10-09T18:20:50Z") == "2007-10-09T18:20:50Z"
    assert parse_rdap_date("2001-01-13T00:12:14.754Z") == "2001-01-13T00:12:14Z"
    assert parse_rdap_date("2026-08-12T08:47:19.41Z") == "2026-08-12T08:47:19Z"
    assert parse_rdap_date("2025-10-29T03:51:11.009091Z") == "2025-10-29T03:51:11Z"
    assert parse_rdap_date("2025-10-29T03:51:11.123456789Z") == "2025-10-29T03:51:11Z"
    assert parse_rdap_date("2028-10-09T18:20:50.000+00:00") == "2028-10-09T18:20:50Z"
    assert parse_rdap_date("2028-10-09T20:20:50+02:00") == "2028-10-09T18:20:50Z"
    assert parse_rdap_date("2028-10-09T18:20:50") == "2028-10-09T18:20:50Z"
    # offsets without a colon aren't RFC 3339, but some servers send them (and python 3.10 can't parse them)
    assert parse_rdap_date("2020-01-01T00:00:00+0000") == "2020-01-01T00:00:00Z"
    assert parse_rdap_date("2028-10-09T13:20:50.5-0500") == "2028-10-09T18:20:50Z"
    assert parse_rdap_date("not a date") is None
    assert parse_rdap_date("") is None
    assert parse_rdap_date(None) is None


def test_rdap_placeholders():
    for value in (
        "REDACTED FOR PRIVACY",
        "REDACTED REGISTRANT",
        "Privacy service provided by WITHHELD FOR PRIVACY LLC",
        "Data Protected",
        "Domains By Proxy, LLC",
        "Contact Privacy Inc. Customer 0123",
        "WhoisGuard Protected",
        "Redacted for GDPR",
        "Not Disclosed",
        "Statutory Masking Enabled",
        "Identity Protection Service",
        "Super Privacy Service LTD c/o Dynadot",
        "PrivacyGuardian.org llc",
        "Hidden",
        "b9ea79ab741f464db85514b28cc28ed9.protect@withheldforprivacy.com",
        "redacted@nominet.uk",
        # godaddy
        "Registration Private",
        # porkbun
        "Private by Design, LLC",
        # name.com
        "Domain Protection Services, Inc.",
        "On behalf of example.com owner",
        "Whois Privacy Protection Service, Inc.",
        "abc123@domainsbyproxy.com",
        "evilcorp.com@contactprivacy.com",
    ):
        assert is_placeholder(value), value
    for value in (
        "GitHub, Inc.",
        "British Broadcasting Corporation",
        "hostmaster@github.com",
        # real organizations and addresses that merely contain privacy-related words
        "Privacy International",
        "Electronic Privacy Information Center",
        "Proxy Networks, Inc.",
        "privacy@apple.com",
        "x@protectwise.com",
        "proxy@evilcorp.com",
        "",
        None,
    ):
        assert not is_placeholder(value), value

    # proxy services are placeholders, but not every placeholder is a proxy service
    for value in ("Domains By Proxy, LLC", "Whois Privacy Protection Service, Inc.", "Private by Design, LLC"):
        assert is_proxy_service(value), value
    for value in ("REDACTED FOR PRIVACY", "REDACTED REGISTRANT", "GitHub, Inc.", "redacted@nominet.uk", None):
        assert not is_proxy_service(value), value


def registrant_record(*vcard_properties, rdap_conformance=None, redacted=None):
    """A minimal RDAP domain response with a registrant entity."""
    rdap_json = {
        "ldhName": "evilcorp.com",
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [list(p) for p in vcard_properties]]}],
    }
    if rdap_conformance is not None:
        rdap_json["rdapConformance"] = rdap_conformance
    if redacted is not None:
        rdap_json["redacted"] = redacted
    return rdap_json


def test_rdap_proxy_country():
    # the proxy service's address isn't the registrant's, even when the proxy is only named in fn
    record = normalize_rdap(
        registrant_record(
            ["fn", {}, "text", "Whois Privacy Protection Service, Inc."],
            ["adr", {"cc": "PA"}, "text", ["", "", "", "", "", "", ""]],
        )
    )
    assert record["registrant_name"] is None
    assert record["registrant_org"] is None
    assert record["registrant_country"] is None
    assert record["registrant_redacted"] is True

    # a plain redaction keeps the country, which registrars still publish
    record = normalize_rdap(
        registrant_record(
            ["fn", {}, "text", "REDACTED FOR PRIVACY"],
            ["org", {}, "text", "REDACTED FOR PRIVACY"],
            ["adr", {"cc": "us"}, "text", ["", "", "", "", "", "", ""]],
        )
    )
    assert record["registrant_org"] is None
    assert record["registrant_country"] == "US"
    assert record["registrant_redacted"] is True

    # a proxy fn with a real org: the address belongs to the org
    record = normalize_rdap(
        registrant_record(
            ["fn", {}, "text", "Registration Private"],
            ["org", {}, "text", "Evil Corp"],
            ["adr", {"cc": "DE"}, "text", ["", "", "", "", "", "", ""]],
        )
    )
    assert record["registrant_org"] == "Evil Corp"
    assert record["registrant_country"] == "DE"


def test_rdap_vcard():
    # org as a list of units, country from params.cc
    vcard = parse_vcard(
        [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Jane Doe"],
                ["org", {"type": "work"}, "text", ["Evil Corp", "IT Department"]],
                ["email", {}, "text", "jane@evilcorp.com"],
                ["adr", {"cc": "DE"}, "text", ["", "", "Street", "Berlin", "", "10115", ""]],
            ],
        ]
    )
    assert vcard == {"fn": "Jane Doe", "org": "Evil Corp", "email": "jane@evilcorp.com", "country": "DE"}
    # country falls back to the last adr component
    vcard = parse_vcard(["vcard", [["adr", {}, "text", ["", "", "", "", "", "", "FR"]]]])
    assert vcard["country"] == "FR"
    # entity with all data removed
    vcard = parse_vcard(["vcard", [["version", {}, "text", "4.0"], ["contact-uri", {}, "uri", "https://x"]]])
    assert vcard == {"fn": None, "org": None, "email": None, "country": None}
    # garbage
    assert parse_vcard(None) == {"fn": None, "org": None, "email": None, "country": None}
    assert parse_vcard(["vcard", [["fn"], "junk"]]) == {"fn": None, "org": None, "email": None, "country": None}


def test_rdap_bootstrap_matching():
    services = bootstrap_services(rdap_sample("iana_dns_bootstrap_trimmed"))
    assert bootstrap_match(services, "github.com") == ["https://rdap.verisign.com/com/v1/"]
    # one service entry with multiple TLDs
    assert bootstrap_match(services, "evilcorp.app") == ["https://pubapi.registry.google/rdap/"]
    assert bootstrap_match(services, "evilcorp.dev") == ["https://pubapi.registry.google/rdap/"]
    # co.uk resolves through uk
    assert bootstrap_match(services, "bbc.co.uk") == ["https://rdap.nominet.uk/uk/"]
    # missing from the bootstrap
    assert bootstrap_match(services, "evilcorp.de") == []
    # the domain itself is never matched, only its suffixes
    assert bootstrap_match(services, "com") == []
    # longest suffix wins, https is preferred
    services = bootstrap_services(
        {
            "services": [
                [["uk"], ["https://rdap.nominet.uk/uk/"]],
                [["co.uk"], ["http://rdap.example.net/", "https://rdap.example.net/"]],
                [["bad"], ["ftp://nope/"]],
                ["garbage"],
            ]
        }
    )
    assert bootstrap_match(services, "bbc.co.uk") == ["https://rdap.example.net/", "http://rdap.example.net/"]
    assert bootstrap_match(services, "bbc.org.uk") == ["https://rdap.nominet.uk/uk/"]
    assert "bad" not in services


def test_rdap_normalize_full_record():
    registry = normalize_rdap(rdap_sample("verisign_com_github"), rdap_server=VERISIGN_GITHUB)
    assert registry == {
        "domain": "github.com",
        "registrar": "MarkMonitor Inc.",
        "registrar_iana_id": "292",
        "registrant_org": None,
        "registrant_name": None,
        "registrant_email": None,
        "registrant_country": None,
        "registrant_redacted": False,
        "created": "2007-10-09T18:20:50Z",
        "updated": "2026-09-07T09:22:52Z",
        "expires": "2028-10-09T18:20:50Z",
        "rdap_updated": "2026-10-01T21:04:58Z",
        "nameservers": GITHUB_NAMESERVERS,
        "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
        "rdap_server": VERISIGN_GITHUB,
    }
    assert registrar_link(rdap_sample("verisign_com_github")) == MARKMONITOR_GITHUB

    # registrar record: name/email/address redacted, but org + country are still there
    registrar = normalize_rdap(rdap_sample("registrar_markmonitor_github"), rdap_server=MARKMONITOR_GITHUB)
    assert registrar["registrant_org"] == "GitHub, Inc."
    assert registrar["registrant_country"] == "US"
    assert registrar["registrant_name"] is None
    assert registrar["registrant_email"] is None
    assert registrar["registrant_redacted"] is True
    # registrar's expiration differs from the registry's
    assert registrar["expires"] == "2028-10-09T00:00:00Z"
    # fractional seconds and +00:00 offsets are normalized
    assert registrar["rdap_updated"] == "2026-10-01T21:00:23Z"

    merged = merge_records(registry, registrar)
    assert merged["registrant_org"] == "GitHub, Inc."
    assert merged["registrant_country"] == "US"
    assert merged["registrant_redacted"] is True
    # registry is authoritative for registrar + dates
    assert merged["registrar"] == "MarkMonitor Inc."
    assert merged["expires"] == "2028-10-09T18:20:50Z"
    assert merged["rdap_updated"] == "2026-10-01T21:04:58Z"
    assert merged["rdap_server"] == VERISIGN_GITHUB
    assert merged["registrar_rdap_server"] == MARKMONITOR_GITHUB


def test_rdap_merge_redaction_flag():
    # the registry declares a registrant redaction (RFC 9537), but the registrar has the full registrant data
    redacted_registrant = [{"name": {"type": "Registrant Name"}, "method": "removal"}]
    registry = normalize_rdap(registrant_record(rdap_conformance=["redacted"], redacted=redacted_registrant))
    assert registry["registrant_redacted"] is True
    registrar = normalize_rdap(
        registrant_record(
            ["fn", {}, "text", "Jane Doe"],
            ["org", {}, "text", "Evil Corp"],
            ["email", {}, "text", "Jane@EvilCorp.com"],
            ["adr", {"cc": "DE"}, "text", ["", "", "", "", "", "", ""]],
        )
    )
    assert registrar["registrant_redacted"] is False
    merged = merge_records(registry, registrar)
    assert merged["registrant_name"] == "Jane Doe"
    assert merged["registrant_email"] == "jane@evilcorp.com"
    assert merged["registrant_redacted"] is False

    # the registrar has no registrant data: the registry's flag stands
    merged = merge_records(registry, normalize_rdap({"ldhName": "evilcorp.com"}))
    assert merged["registrant_org"] is None
    assert merged["registrant_redacted"] is True


def test_rdap_normalize_redacted_record():
    # RFC 9537 "redacted" member + privacy proxy registrant + "registrar expiration" only
    record = normalize_rdap(rdap_sample("registrar_namecheap_namecheap"))
    assert record["domain"] == "namecheap.com"
    assert record["registrar"] == "NAMECHEAP INC"
    assert record["registrar_iana_id"] == "1068"
    assert record["registrant_redacted"] is True
    assert record["registrant_org"] is None
    assert record["registrant_name"] is None
    assert record["registrant_email"] is None
    # the address belongs to the privacy service, not the registrant
    assert record["registrant_country"] is None
    assert record["expires"] == "2032-08-11T16:15:25Z"
    # no related link to follow
    assert registrar_link(rdap_sample("registrar_namecheap_namecheap")) is None

    # PIR redacts only the registry domain ID, which isn't registrant data
    record = normalize_rdap(rdap_sample("pir_org_wikipedia"))
    assert record["registrant_redacted"] is False
    assert record["registrant_org"] is None

    # ccTLD: no IANA registrar ID, trailing dots on nameservers, redaction remarks
    record = normalize_rdap(rdap_sample("nominet_uk_bbc"))
    assert record["registrar"] == "British Broadcasting Corporation"
    assert record["registrar_iana_id"] is None
    assert record["nameservers"] == ["ddns0.bbc.co.uk", "ddns0.bbc.com"]
    assert record["registrant_redacted"] is True
    assert record["registrant_email"] is None
    assert record["updated"] == "2025-10-29T03:51:11Z"
    assert record["rdap_updated"] == "2026-10-01T21:06:12Z"

    # registrant nested inside the registrar entity
    record = normalize_rdap(
        {
            "ldhName": "evilcorp.fr",
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Evil Registrar"]]],
                    "entities": [
                        {
                            "roles": ["technical", "registrant"],
                            "vcardArray": ["vcard", [["org", {}, "text", "Evil Corp"]]],
                        }
                    ],
                }
            ],
        }
    )
    assert record["registrar"] == "Evil Registrar"
    assert record["registrant_org"] == "Evil Corp"
    assert record["registrant_redacted"] is False
    assert record["nameservers"] == []
    assert record["status"] == []


@pytest.mark.asyncio
async def test_rdap_lookup_registrar_follow(rdap, blasthttp_mock):
    blasthttp_mock.add_response(url=VERISIGN_GITHUB, json=rdap_sample("verisign_com_github"))
    blasthttp_mock.add_response(url=MARKMONITOR_GITHUB, json=rdap_sample("registrar_markmonitor_github"))

    record = await rdap.lookup("GitHub.com")
    assert record["domain"] == "github.com"
    assert record["registrar"] == "MarkMonitor Inc."
    assert record["registrar_iana_id"] == "292"
    assert record["registrant_org"] == "GitHub, Inc."
    assert record["registrant_country"] == "US"
    assert record["registrant_name"] is None
    assert record["registrant_redacted"] is True
    assert record["created"] == "2007-10-09T18:20:50Z"
    assert record["expires"] == "2028-10-09T18:20:50Z"
    assert record["nameservers"] == GITHUB_NAMESERVERS
    assert record["rdap_server"] == VERISIGN_GITHUB
    assert record["registrar_rdap_server"] == MARKMONITOR_GITHUB
    assert "raw" not in record

    # without following the registrar, there's no registrant data
    record = await rdap.lookup("github.com", follow_registrar=False, include_raw=True)
    assert record["registrar"] == "MarkMonitor Inc."
    assert record["registrant_org"] is None
    assert "registrar_rdap_server" not in record
    assert record["raw"]["registry"]["ldhName"] == "GITHUB.COM"
    assert "registrar" not in record["raw"]


@pytest.mark.asyncio
async def test_rdap_lookup_registrar_failure(rdap, blasthttp_mock):
    # registrar server is down: we still get the registry data
    blasthttp_mock.add_response(url=PIR_WIKIPEDIA, json=rdap_sample("pir_org_wikipedia"))
    calls = count_requests(blasthttp_mock, MARKMONITOR_WIKIPEDIA, MockResponse(status_code=503))
    record = await rdap.lookup("wikipedia.org")
    assert calls == [MARKMONITOR_WIKIPEDIA]
    assert record["domain"] == "wikipedia.org"
    assert record["registrar"] == "MarkMonitor Inc."
    assert record["expires"] == "2027-01-13T00:12:14Z"
    assert record["rdap_server"] == PIR_WIKIPEDIA
    assert "registrar_rdap_server" not in record
    assert rdap.server_state(MARKMONITOR_WIKIPEDIA).consecutive_failures == 1


@pytest.mark.asyncio
async def test_rdap_lookup_cctld(rdap, blasthttp_mock):
    blasthttp_mock.add_response(url=NOMINET_BBC, json=rdap_sample("nominet_uk_bbc"))
    record = await rdap.lookup("bbc.co.uk")
    assert record["domain"] == "bbc.co.uk"
    assert record["registrar"] == "British Broadcasting Corporation"
    assert record["registrant_redacted"] is True
    assert record["rdap_server"] == NOMINET_BBC


@pytest.mark.asyncio
async def test_rdap_lookup_bootstrap_miss(rdap, blasthttp_mock):
    calls = count_requests(blasthttp_mock, re.compile(r".*/domain/.*"), MockResponse(status_code=500))
    assert await rdap.lookup("evilcorp.de") is None
    assert await rdap.lookup("com") is None
    assert await rdap.lookup("") is None
    assert calls == []


@pytest.mark.asyncio
async def test_rdap_lookup_bootstrap_failure(helpers, blasthttp_mock):
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)
    calls = count_requests(blasthttp_mock, RDAP_BOOTSTRAP_URL, MockResponse(status_code=500, text="error"))
    rdap = RDAPHelper(helpers)
    # concurrent lookups share one download, and its failure
    results = await asyncio.gather(*[rdap.lookup(f"evilcorp{i}.com") for i in range(5)])
    assert results == [None] * 5
    assert len(calls) == 1
    # no new attempt while backing off
    assert await rdap.bootstrap() == {}
    assert await rdap.lookup("github.com") is None
    assert len(calls) == 1
    assert not helpers.cache_filename(RDAP_BOOTSTRAP_URL).exists()
    # once the backoff is over, it's downloaded again
    rdap._bootstrap_failed_at -= rdap.bootstrap_retry_seconds
    assert await rdap.bootstrap() == {}
    assert len(calls) == 2
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_rdap_bootstrap_memoized(helpers, blasthttp_mock):
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)
    calls = count_requests(
        blasthttp_mock,
        RDAP_BOOTSTRAP_URL,
        MockResponse(status_code=200, json=rdap_sample("iana_dns_bootstrap_trimmed")),
    )
    blasthttp_mock.add_response(url=PIR_WIKIPEDIA, json=rdap_sample("pir_org_wikipedia"))
    rdap = RDAPHelper(helpers)
    rdap.configure(server_interval=0)
    results = await asyncio.gather(*[rdap.lookup("wikipedia.org", follow_registrar=False) for _ in range(5)])
    assert all(r["registrar"] == "MarkMonitor Inc." for r in results)
    assert await rdap.base_urls("github.com") == ["https://rdap.verisign.com/com/v1/"]
    assert len(calls) == 1
    helpers.cache_filename(RDAP_BOOTSTRAP_URL).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_rdap_lookup_404(rdap, blasthttp_mock):
    # verisign returns an empty body for nonexistent domains
    url = "https://rdap.verisign.com/com/v1/domain/doesnotexist-evilcorp.com"
    blasthttp_mock.add_response(url=url, status_code=404, text="", headers={"Content-Type": "application/rdap+json"})
    assert await rdap.lookup("doesnotexist-evilcorp.com") is None
    # a 404 is not a server failure
    state = rdap.server_state(url)
    assert state.consecutive_failures == 0
    assert state.tripped is False


def record_cooldowns(state):
    """Record every cooldown requested on a server."""
    cooldowns = []
    cool_down = state.cool_down

    def _cool_down(seconds):
        cooldowns.append(seconds)
        cool_down(seconds)

    state.cool_down = _cool_down
    return cooldowns


@pytest.mark.asyncio
async def test_rdap_lookup_429(rdap, blasthttp_mock):
    # the default backoff and the cap are clearly different from the server's Retry-After
    rdap.configure(default_retry_after=5, max_retry_after=1)

    # a Retry-After below the cap is honored
    calls = count_requests(
        blasthttp_mock,
        VERISIGN_GITHUB,
        MockResponse(status_code=429, headers={"Retry-After": "0.05"}),
        MockResponse(status_code=200, json=rdap_sample("verisign_com_github")),
    )
    state = rdap.server_state(VERISIGN_GITHUB)
    cooldowns = record_cooldowns(state)
    record = await rdap.lookup("github.com", follow_registrar=False)
    assert len(calls) == 2
    assert cooldowns == [0.05]
    assert record["registrar"] == "MarkMonitor Inc."
    assert state.rate_limited == 1
    assert state.consecutive_failures == 0

    # a Retry-After above the cap: don't retry early (we'd only get a 429 again), honor the full cooldown,
    # and skip the server without waiting until it's over
    url = "https://rdap.verisign.com/net/v1/domain/evilcorp.net"
    calls = count_requests(blasthttp_mock, url, MockResponse(status_code=429, headers={"Retry-After": "3600"}))
    state = rdap.server_state(url)
    cooldowns = record_cooldowns(state)
    assert await rdap.lookup("evilcorp.net") is None
    assert len(calls) == 1
    assert cooldowns == [3600]
    assert state.cooldown_remaining() > 3500
    start = time.monotonic()
    assert await rdap.lookup("evilcorp.net") is None
    assert time.monotonic() - start < 0.5
    assert len(calls) == 1
    # being rate limited isn't a server failure
    assert state.consecutive_failures == 0
    assert state.tripped is False

    # rate limited forever, without a Retry-After header: capped backoff, give up after max_retries
    rdap.configure(default_retry_after=0.05, max_retry_after=0.02, max_retries=2)
    url = "https://rdap.nic.fr/domain/evilcorp.fr"
    calls = count_requests(blasthttp_mock, url, MockResponse(status_code=429))
    state = rdap.server_state(url)
    cooldowns = record_cooldowns(state)
    assert await rdap.lookup("evilcorp.fr") is None
    assert len(calls) == 3
    assert cooldowns == [0.02, 0.02, 0.02]
    assert state.consecutive_failures == 0
    assert state.tripped is False


@pytest.mark.asyncio
async def test_rdap_server_interval(rdap, blasthttp_mock):
    rdap.configure(server_interval=0.3)
    verisign = time_requests(
        blasthttp_mock,
        re.compile(r"https://rdap\.verisign\.com/com/v1/domain/.*"),
        MockResponse(status_code=200, json=rdap_sample("verisign_com_github")),
    )
    pir = time_requests(
        blasthttp_mock, PIR_WIKIPEDIA, MockResponse(status_code=200, json=rdap_sample("pir_org_wikipedia"))
    )
    start = time.monotonic()
    results = await asyncio.gather(
        *[rdap.lookup(f"evilcorp{i}.com", follow_registrar=False) for i in range(3)],
        rdap.lookup("wikipedia.org", follow_registrar=False),
    )
    assert all(results)
    # requests to the same server are spaced by server_interval
    assert len(verisign) == 3
    starts = sorted(s for _, s, _ in verisign)
    assert all(b - a >= 0.29 for a, b in zip(starts, starts[1:])), starts
    # but a different server isn't held back by them
    assert len(pir) == 1
    assert pir[0][1] - start < 0.2


@pytest.mark.asyncio
async def test_rdap_server_isolation(rdap, blasthttp_mock):
    # several lookups stuck on a slow server, plus one on another server
    rdap.configure(server_concurrency=2)
    verisign = time_requests(
        blasthttp_mock,
        re.compile(r"https://rdap\.verisign\.com/com/v1/domain/.*"),
        MockResponse(status_code=200, json=rdap_sample("verisign_com_github")),
        delay=0.3,
    )
    pir = time_requests(
        blasthttp_mock, PIR_WIKIPEDIA, MockResponse(status_code=200, json=rdap_sample("pir_org_wikipedia"))
    )
    start = time.monotonic()
    slow = [asyncio.create_task(rdap.lookup(f"evilcorp{i}.com", follow_registrar=False)) for i in range(6)]
    record = await rdap.lookup("wikipedia.org", follow_registrar=False)
    assert record["registrar"] == "MarkMonitor Inc."
    assert time.monotonic() - start < 0.2
    assert all(await asyncio.gather(*slow))
    assert len(pir) == 1
    # server_concurrency limits how many requests are in flight to the slow server at once
    assert len(verisign) == 6
    max_in_flight = max(sum(1 for _, s, e in verisign if s <= t < e) for _, t, _ in verisign)
    assert max_in_flight == 2

    # a server in a long 429 cooldown fails fast instead of tying up the caller
    rdap.server_state("https://rdap.verisign.com/com/v1/").cool_down(3600)
    start = time.monotonic()
    results = await asyncio.gather(
        *[rdap.lookup(f"evilcorp{i}.com", follow_registrar=False) for i in range(10, 15)],
        rdap.lookup("wikipedia.org", follow_registrar=False),
    )
    assert time.monotonic() - start < 0.5
    assert results[:5] == [None] * 5
    assert results[5]["registrar"] == "MarkMonitor Inc."
    assert len(verisign) == 6


@pytest.mark.asyncio
async def test_rdap_wait_turn():
    state = RDAPServerState("rdap.evilcorp.com", concurrency=2, interval=0.2)
    assert await state.wait_turn() is True
    # a cooldown set while another request is waiting for its turn is honored, and not erased
    start = time.monotonic()
    waiter = asyncio.create_task(state.wait_turn())
    await asyncio.sleep(0.05)
    state.cool_down(0.5)
    assert await waiter is True
    assert time.monotonic() - start >= 0.5
    assert state.cooldown_remaining() > 0.1
    # a wait longer than max_wait returns immediately
    state.cool_down(3600)
    start = time.monotonic()
    assert await state.wait_turn(max_wait=1) is False
    assert time.monotonic() - start < 0.5


@pytest.mark.asyncio
async def test_rdap_circuit_breaker(rdap, blasthttp_mock):
    rdap.configure(failure_threshold=3)
    calls = count_requests(
        blasthttp_mock, re.compile(r"https://rdap\.verisign\.com/com/v1/domain/.*"), MockResponse(status_code=500)
    )
    blasthttp_mock.add_response(url=PIR_WIKIPEDIA, json=rdap_sample("pir_org_wikipedia"))

    for i in range(6):
        assert await rdap.lookup(f"evilcorp{i}.com") is None
    # the server is skipped after 3 consecutive failures
    assert len(calls) == 3
    state = rdap.server_state("https://rdap.verisign.com/com/v1/")
    assert state.tripped is True

    # other servers are unaffected
    record = await rdap.lookup("wikipedia.org", follow_registrar=False)
    assert record["registrar"] == "MarkMonitor Inc."

    # connection errors and invalid JSON count as failures too
    rdap.configure(failure_threshold=2)
    blasthttp_mock.add_response(url="https://rdap.nic.fr/domain/evilcorp.fr", text="<html>not json</html>")
    assert await rdap.lookup("evilcorp.fr") is None
    # no mock registered == connection error
    assert await rdap.lookup("evilcorp.dev") is None
    assert await rdap.lookup("evilcorp.app") is None
    assert rdap.server_state("https://rdap.nic.fr/").consecutive_failures == 1
    assert rdap.server_state("https://pubapi.registry.google/rdap/").tripped is True


@pytest.mark.asyncio
async def test_rdap_failures_reset(rdap, blasthttp_mock):
    # failures only trip the breaker if they're consecutive: a 404 means the server is alive
    rdap.configure(failure_threshold=3)
    calls = count_requests(
        blasthttp_mock,
        re.compile(r"https://rdap\.verisign\.com/com/v1/domain/.*"),
        MockResponse(status_code=500),
        MockResponse(status_code=500),
        MockResponse(status_code=404, text=""),
        MockResponse(status_code=500),
        MockResponse(status_code=500),
        MockResponse(status_code=200, json=rdap_sample("verisign_com_github")),
        MockResponse(status_code=500),
        MockResponse(status_code=500),
    )
    for i in range(5):
        assert await rdap.lookup(f"evilcorp{i}.com", follow_registrar=False) is None
    state = rdap.server_state("https://rdap.verisign.com/com/v1/")
    assert len(calls) == 5
    assert state.consecutive_failures == 2
    assert state.tripped is False
    # so does a 200
    assert await rdap.lookup("evilcorp5.com", follow_registrar=False)
    assert state.consecutive_failures == 0
    for i in range(6, 8):
        assert await rdap.lookup(f"evilcorp{i}.com", follow_registrar=False) is None
    assert len(calls) == 8
    assert state.consecutive_failures == 2
    assert state.tripped is False


@pytest.mark.asyncio
async def test_rdap_circuit_breaker_reset(rdap, blasthttp_mock):
    rdap.configure(failure_threshold=2, circuit_reset_seconds=0.2)
    calls = count_requests(
        blasthttp_mock, re.compile(r"https://rdap\.verisign\.com/com/v1/domain/.*"), MockResponse(status_code=500)
    )
    for i in range(3):
        assert await rdap.lookup(f"evilcorp{i}.com") is None
    state = rdap.server_state("https://rdap.verisign.com/com/v1/")
    assert len(calls) == 2
    assert state.tripped is True
    # after circuit_reset_seconds, one request is let through (half-open)...
    await asyncio.sleep(0.25)
    assert await rdap.lookup("evilcorp3.com") is None
    assert len(calls) == 3
    # ...and a single failure trips it again
    assert state.tripped is True
    assert await rdap.lookup("evilcorp4.com") is None
    assert len(calls) == 3
    # reset() closes it right away
    state.reset()
    assert state.consecutive_failures == 0
    assert await rdap.lookup("evilcorp5.com") is None
    assert len(calls) == 4
    assert state.tripped is False


@pytest.mark.asyncio
async def test_rdap_helper_attached(helpers):
    assert isinstance(helpers.rdap, RDAPHelper)
    assert helpers.rdap is helpers.rdap
