from ..bbot_fixtures import *  # noqa: F403

from bbot.core.helpers.whois import (
    is_placeholder,
    is_proxy_service,
    normalize_status,
    parse_whois,
    parse_whois_date,
)
from bbot.test.whois_samples import whois_sample


def test_whois_parsing():
    github = parse_whois("github.com", whois_sample("github.com"))
    assert github["registrar"] == "MarkMonitor, Inc."
    assert github["registrar_iana_id"] == "292"
    assert github["registrant_org"] == "GitHub, Inc."
    assert github["registrant_country"] == "US"
    # email is a web form link, not an address
    assert github["registrant_redacted"] is True
    assert "registrant_email" not in github
    assert github["created"] == "2007-10-09T18:20:50Z"
    # the registry's expiry wins over the registrar's midnight-truncated copy
    assert github["expires"] == "2028-10-09T18:20:50Z"
    assert github["nameservers"] == [
        "dns1.p08.nsone.net",
        "dns2.p08.nsone.net",
        "dns3.p08.nsone.net",
        "dns4.p08.nsone.net",
        "ns-1283.awsdns-32.org",
        "ns-1707.awsdns-21.co.uk",
        "ns-421.awsdns-52.com",
        "ns-520.awsdns-01.net",
    ]
    assert github["status"] == ["client delete prohibited", "client transfer prohibited", "client update prohibited"]
    assert github["whois_server"] == "whois.markmonitor.com"

    # privacy service: org, name, and email are placeholders, and the country belongs to the service
    namecheap = parse_whois("namecheap.com", whois_sample("namecheap.com"))
    assert namecheap["registrar"] == "NAMECHEAP INC"
    assert namecheap["registrant_redacted"] is True
    for field in ("registrant_org", "registrant_name", "registrant_email", "registrant_country"):
        assert field not in namecheap

    wikipedia = parse_whois("wikipedia.org", whois_sample("wikipedia.org"))
    assert wikipedia["registrar"] == "MarkMonitor Inc."
    assert wikipedia["expires"] == "2027-01-13T00:12:14Z"
    assert wikipedia["registrant_redacted"] is False

    assert parse_whois("evilcorp.com", "No match for domain EVILCORP.COM.") is None


def test_whois_helpers():
    assert is_placeholder("REDACTED FOR PRIVACY")
    assert is_placeholder("Select Request Email Form at https://domains.markmonitor.com/whois/github.com")
    assert is_placeholder("b9ea79ab741f464db85514b28cc28ed9.protect@withheldforprivacy.com")
    assert not is_placeholder("privacy@apple.com")
    assert not is_placeholder("GitHub, Inc.")
    assert is_proxy_service("Domains By Proxy, LLC")
    assert not is_proxy_service("REDACTED FOR PRIVACY")
    assert parse_whois_date("2001-01-13T02:12:14.754+02:00") == "2001-01-13T00:12:14Z"
    assert parse_whois_date("2001-01-13T00:12:14Z") == "2001-01-13T00:12:14Z"
    assert parse_whois_date("tomorrow") is None
    assert parse_whois_date(None) is None
    assert normalize_status("clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited") == (
        "client delete prohibited"
    )
    assert normalize_status("ok") == "ok"


@pytest.mark.asyncio
async def test_whois_cache_shared_with_baddns(helpers, monkeypatch):
    """The WHOIS cache is baddns's own, so each domain is queried once no matter who asks first."""
    import whois
    from whois.parser import WhoisEntry
    from baddns.lib.whoismanager import WhoisManager

    queried = []

    def fake_whois(domain, **kwargs):
        queried.append(domain)
        return WhoisEntry.load(domain, whois_sample(domain))

    monkeypatch.setattr(whois, "whois", fake_whois)
    WhoisManager.clear_cache()
    try:
        assert helpers.whois.cache is WhoisManager._cache

        # a domain baddns already fetched is parsed without a second query
        WhoisManager._cache["github.com"] = {
            "type": "response",
            "data": WhoisEntry.load("github.com", whois_sample("github.com")),
        }
        github = await helpers.whois.lookup("github.com")
        assert github["registrar"] == "MarkMonitor, Inc."
        assert queried == []

        # ...and our own result lands in the shape baddns reads back
        namecheap = await helpers.whois.lookup("namecheap.com")
        assert namecheap["registrar"] == "NAMECHEAP INC"
        assert queried == ["namecheap.com"]
        manager = WhoisManager("www.namecheap.com")
        await manager.dispatchWHOIS()
        assert manager.whois_result["type"] == "response"
        assert queried == ["namecheap.com"]

        # failures are cached too, so a dead domain isn't retried all scan
        monkeypatch.setattr(whois, "whois", lambda domain, **kwargs: 1 / 0)
        assert await helpers.whois.lookup("evilcorp.com") is None
        assert await helpers.whois.lookup("evilcorp.com") is None
        assert WhoisManager._cache["evilcorp.com"]["type"] == "error"

        helpers.whois.clear_cache()
        assert WhoisManager._cache == {}
    finally:
        WhoisManager.clear_cache()


@pytest.mark.asyncio
async def test_whois_works_without_baddns(helpers, monkeypatch):
    """baddns is an optional cache partner, never a dependency: WHOIS works fully on its own."""
    import builtins
    import whois
    from whois.parser import WhoisEntry
    from baddns.lib.whoismanager import WhoisManager
    from bbot.core.helpers.whois import WhoisHelper

    real_import = builtins.__import__

    def no_baddns(name, *args, **kwargs):
        if name.split(".")[0] == "baddns":
            raise ImportError("No module named 'baddns'")
        return real_import(name, *args, **kwargs)

    WhoisManager.clear_cache()
    try:
        monkeypatch.setattr(builtins, "__import__", no_baddns)
        monkeypatch.setattr(whois, "whois", lambda domain, **kw: WhoisEntry.load(domain, whois_sample(domain)))

        helper = WhoisHelper(helpers)
        assert helper.cache is not WhoisManager._cache

        record = await helper.lookup("github.com")
        assert record["registrar"] == "MarkMonitor, Inc."
        assert record["nameservers"]
        # cached privately, and nothing reached baddns
        assert set(helper.cache) == {"github.com"}
        assert WhoisManager._cache == {}

        # the private cache still serves hits and still absorbs failures
        assert (await helper.lookup("github.com"))["registrar"] == "MarkMonitor, Inc."
        monkeypatch.setattr(whois, "whois", lambda domain, **kw: 1 / 0)
        assert await helper.lookup("evilcorp.com") is None
        assert helper.cache["evilcorp.com"]["type"] == "error"
        helper.clear_cache()
        assert helper.cache == {}
    finally:
        WhoisManager.clear_cache()
