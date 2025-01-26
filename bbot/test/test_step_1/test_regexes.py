import pytest
import traceback

from ..bbot_fixtures import *  # noqa F401
from bbot.core.helpers import regexes
from bbot.errors import ValidationError
from bbot.core.event.helpers import get_event_type


# NOTE: :2001:db8:: will currently cause an exception...
# e.g. raised unknown error: split_port() failed to parse netloc ":2001:db8::"


def test_ip_regexes():
    bad_ip = [
        "203.0..113.0",  # double dot typeo
        ".0.113.0",  # Partial match
        "203.0.113.",  # Partial match
        "203.0.113.0:80",  # correctly formatted with :port appended
        "255.255.255.256",  # octet greater than 255
        "256.255.255.255",  # octet greater than 255
        "2001:db8:::80",  # incorrectly formatted with :port appended
        "[2001:db8::]:80",  # correctly formatted with :port appended
        "2001:db8:g::",  # includes non-hex character,
        "2001.db8.80",  # weird dot separated thing that might actually resolve as a DNS_NAME
        "9e:3e:53:29:43:64",  # MAC address, poor regex patterning will often detect these.
    ]

    good_ip = [
        "0.0.0.0",
        "10.0.0.0",
        "10.255.255.255",
        "127.0.0.0",
        "127.0.0.1",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "203.0.113.0",
        "203.0.113.0/24",
        "255.255.255.255",
        "::1",
        "2001:db8::",
        "2001:db8::1",
        "2001:db8::1/128",
        "1:1:1:1:1:1:1:1",
        "1::1",
        "ffff::ffff",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]

    ip_address_regexes = regexes.event_type_regexes["IP_ADDRESS"]

    for ip in bad_ip:
        for r in ip_address_regexes:
            assert not r.match(ip), f"BAD IP ADDRESS: {ip} matched regex: {r}"

        try:
            event_type, _ = get_event_type(ip)
            if event_type == "OPEN_TCP_PORT":
                if ip.startswith("["):
                    assert ip == "[2001:db8::]:80"
                else:
                    assert ip == "203.0.113.0:80"
                continue
            if event_type == "DNS_NAME":
                if ip.startswith("2001"):
                    assert ip == "2001.db8.80"
                elif ip.startswith("255"):
                    assert ip == "255.255.255.256"
                elif ip.startswith("256"):
                    assert ip == "256.255.255.255"
                else:
                    assert ip == "203.0.113."
                continue
            pytest.fail(f"BAD IP ADDRESS: {ip} matched returned event type: {event_type}")
        except ValidationError:
            continue
        except Exception as e:
            pytest.fail(f"BAD IP ADDRESS: {ip} raised unknown error: {e}")

    for ip in good_ip:
        event_type, _ = get_event_type(ip)
        if not event_type == "IP_ADDRESS":
            if ip.endswith("/24"):
                assert ip == "203.0.113.0/24" and event_type == "IP_RANGE", (
                    f"Event type for IP_ADDRESS {ip} was not properly detected"
                )
            else:
                assert ip == "2001:db8::1/128" and event_type == "IP_RANGE", (
                    f"Event type for IP_ADDRESS {ip} was not properly detected"
                )
        else:
            matches = [r.match(ip) for r in ip_address_regexes]
            assert any(matches), f"Good IP ADDRESS {ip} did not match regexes"


def test_ip_range_regexes():
    bad_ip_ranges = [
        "203.0.113.0",
        "203.0.113.0/",
        "203.0.113.0/a",
        "2001:db8::/",
        "2001:db8::/a",
        "evilcorp.com",
        "[2001:db8::]:80",
    ]

    good_ip_ranges = [
        "203.0.113.0/8",
        "203.0.113.255/32",
        "2001:db8::/128",
        "2001:db8::/4",
    ]

    ip_range_regexes = regexes.event_type_regexes["IP_RANGE"]

    for bad_ip_range in bad_ip_ranges:
        for r in ip_range_regexes:
            assert not r.match(bad_ip_range), f"BAD IP_RANGE: {bad_ip_range} matched regex: {r}"

        event_type = ""
        try:
            event_type, _ = get_event_type(bad_ip_range)
            if event_type == "DNS_NAME":
                assert bad_ip_range == "evilcorp.com"
                continue
            if event_type == "IP_ADDRESS":
                assert bad_ip_range == "203.0.113.0"
                continue
            if event_type == "OPEN_TCP_PORT":
                assert bad_ip_range == "[2001:db8::]:80"
                continue
            pytest.fail(f"BAD IP_RANGE: {bad_ip_range} matched returned event type: {event_type}")
        except ValidationError:
            continue
        except Exception as e:
            pytest.fail(f"BAD IP_RANGE: {bad_ip_range} raised unknown error: {e}: {traceback.format_exc()}")

    for good_ip_range in good_ip_ranges:
        matches = [r.match(good_ip_range) for r in ip_range_regexes]
        assert any(matches), f"Good IP_RANGE {good_ip_range} did not match regexes"


def test_dns_name_regexes():
    bad_dns = [
        "-evilcorp.com",  # DNS names cannot begin with a dash
        "evilcorp-.com",  # DNS names cannot end with a dash
        "evilcorp..com",  # DNS names cannot have two consecutive dots
        ".evilcorp.com",  # DNS names cannot begin with a dot
        "ev*lcorp.com",  # DNS names cannot have special characters (other than dash and dot)
        "evilcorp/.com",  # DNS names cannot have slashes
        "evilcorp..",  # DNS names cannot end with a dot
        "evilcorp.com/path",  # Paths are not part of DNS names
        "evilcorp.com:80",  # Ports are not part of DNS names
    ]

    good_dns = [
        "evilcorp.com",
        "www.evilcorp.com",
        "subdomain.evilcorp.com",
        "deep.subdomain.evilcorp.com",
        "evilcorp-test.com",
        "evilcorp_com",
        "evilcorpcom",
        "1.2.3.4",
        "1-2-3.net",
        "single-character.tld",
        "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfa.com",
        "asdfasdfasdfasdfgsdgasdfs.asdfasdfasdfasdfasdf.evilcorp.com",
    ]

    dns_name_regexes = regexes.event_type_regexes["DNS_NAME"]

    for dns in bad_dns:
        for r in dns_name_regexes:
            assert not r.match(dns), f"BAD DNS NAME: {dns} matched regex: {r}"

        try:
            event_type, _ = get_event_type(dns)
            if event_type == "OPEN_TCP_PORT":
                assert dns == "evilcorp.com:80"
                continue
            elif event_type == "IP_ADDRESS":
                assert dns == "1.2.3.4"
                continue
            pytest.fail(f"BAD DNS NAME: {dns} matched returned event type: {event_type}")
        except ValidationError:
            continue
        except Exception as e:
            pytest.fail(f"BAD DNS NAME: {dns} raised unknown error: {e}")

    for dns in good_dns:
        matches = [r.match(dns) for r in dns_name_regexes]
        assert any(matches), f"Good DNS_NAME {dns} did not match regexes"
        event_type, _ = get_event_type(dns)
        if not event_type == "DNS_NAME":
            assert dns == "1.2.3.4" and event_type == "IP_ADDRESS", (
                f"Event type for DNS_NAME {dns} was not properly detected"
            )


def test_open_port_regexes():
    bad_ports = [
        "1.2.3.4",
        "[dead::beef]",
        "evilcorp.com",
        "asdfasdfasdfasdfasdfasdf.asdfasdfasdfasdfasdf.evilcorp.com",
        "asdfasdfasdfasdfasdfasdf.asdfasdfasdfasdfasdf.evilcorp.com/login",
        "asdfasdfasdfasdfasdfasdf.asdfasdfasdfasdfasdf.evilcorp.com:80/login",
        "192.0.2.1:-80",  # Ports cannot be negative
        "192.0.2.1:800000",  # Ports cannot exceed 65535
        "[2001:db8::]:-80",  # Ports cannot be negative
        "[2001:db8::1]:800000",  # Ports cannot exceed 65535
        "[2001:db8::1]:80/login",  # Ports cannot exceed 65535
        "192.0.2.1:notaport",  # Ports must be a number
        "[2001:db8::1]:notaport",  # Ports must be a number
        "192.0.2.1:",  # Ports cannot be empty
        "[2001:db8::1]:",  # Ports cannot be empty
        "2001:db8::1:65535",  # IPv6 ports must be surrounded by []
    ]

    good_ports = [
        "192.0.2.1:80",
        "192.0.2.1:8080",
        "192.0.2.1:65535",
        "localhost:8888",
        "evilcorp.com:8080",
        "asdfasdfasdfasdfasdfasdf.asdfasdfasdfasdfasdfasdf.asdfasdfasdfsadf.evilcorp.com:8080",
        "[2001:db8::1]:80",
        "[2001:db8::1]:8080",
        "[2001:db8::1]:65535",
    ]

    open_port_regexes = regexes.event_type_regexes["OPEN_TCP_PORT"]

    for open_port in bad_ports:
        for r in open_port_regexes:
            assert not r.match(open_port), f"BAD OPEN_TCP_PORT: {open_port} matched regex: {r}"

        try:
            event_type, _ = get_event_type(open_port)
            if event_type == "IP_ADDRESS":
                assert open_port in ("1.2.3.4", "[dead::beef]")
                continue
            elif event_type == "DNS_NAME":
                assert open_port in ("evilcorp.com", "asdfasdfasdfasdfasdfasdf.asdfasdfasdfasdfasdf.evilcorp.com")
                continue
            pytest.fail(f"BAD OPEN_TCP_PORT: {open_port} matched returned event type: {event_type}")
        except ValidationError:
            continue
        except Exception as e:
            pytest.fail(f"BAD OPEN_TCP_PORT: {open_port} raised unknown error: {e}")

    for open_port in good_ports:
        matches = [r.match(open_port) for r in open_port_regexes]
        assert any(matches), f"Good OPEN_TCP_PORT {open_port} did not match regexes"
        event_type, _ = get_event_type(open_port)
        assert event_type == "OPEN_TCP_PORT"


def test_url_regexes():
    bad_urls = [
        "http:/evilcorp.com",
        "http:evilcorp.com",
        "http://evilcorp..com",
        "http:///evilcorp.com",
        "http:// evilcorp.com",
        "http://evilcorp com",
        "http://.com",
        "evilcorp.com",
        "http://ex..ample.com",
        "http://evilcorp..com/path",
        "http://evilcorp tool.com",
        "http://evilcorp.com:this_is_not_a_port/path",
        "http://-evilcorp.com",
        "http://evilcorp-.com",
        "http://evilcorp.com-",
        "http://-evilcorp-.com",
        "http://evilcorp-.com/path",
        "http://evilcorp.com-/path",
        "evilcorp.com/pathasdfasdfasdfasdfgsdgasdfs.asdfasdfasdfasdfasdf.evilcorp.com/path",
        "rhttps://evilcorp.com",
        "https://[e]",
        "https://[1]:80",
    ]

    good_urls = [
        "https://evilcorp.com",
        "http://evilcorp.",
        "https://asdf.www.evilcorp.com",
        "https://asdf.www-test.evilcorp.com",
        "https://a.www-test.evilcorp.c",
        "https://evilcorp.com/asdf?a=b",
        "https://evilcorp.com/asdf/asdf/asdf",
        "https://1.2.3.4/",
        "https://[dead::beef]/",
        "https://[dead:c0de::beef]/",
        "https://asdfasdfasdfasdfasdf.asdfasdfasdfasdfasdfa.sdfasdfasdfasdfsadf.evilcorp.com",
    ]

    url_regexes = regexes.event_type_regexes["URL"]

    for bad_url in bad_urls:
        for r in url_regexes:
            assert not r.match(bad_url), f"BAD URL: {bad_url} matched regex: {r}"

        event_type = ""
        try:
            event_type, _ = get_event_type(bad_url)
            if event_type == "DNS_NAME":
                assert bad_url == "evilcorp.com"
                continue
            pytest.fail(f"BAD URL: {bad_url} matched returned event type: {event_type}")
        except ValidationError:
            continue
        except Exception as e:
            pytest.fail(f"BAD URL: {bad_url} raised unknown error: {e}: {traceback.format_exc()}")

    for good_url in good_urls:
        matches = [r.match(good_url) for r in url_regexes]
        assert any(matches), f"Good URL {good_url} did not match regexes"
        assert get_event_type(good_url)[0] == "URL_UNVERIFIED", (
            f"Event type for URL {good_url} was not properly detected"
        )


@pytest.mark.asyncio
async def test_regex_helper():
    from bbot import Scanner

    scan = Scanner("evilcorp.com", "evilcorp.org", "evilcorp.net", "evilcorp.co.uk")

    dns_name_regexes = regexes.event_type_regexes["DNS_NAME"]

    # re.search
    matches = []
    for r in dns_name_regexes:
        match1 = await scan.helpers.re.search(r, "evilcorp.com")
        if match1:
            matches.append(match1)
        match2 = await scan.helpers.re.search(r, "evilcorp")
        if match2:
            matches.append(match2)
    assert len(matches) == 2
    groups = [m.group() for m in matches]
    assert "evilcorp.com" in groups
    assert "evilcorp" in groups

    subdomains = {"www.evilcorp.com", "www.evilcorp.org", "www.evilcorp.co.uk", "www.evilcorp.net"}
    to_search = "\n".join(list(subdomains) * 2)
    assert len(scan.dns_regexes) == 4

    # re.findall
    matches = []
    for dns_regex in scan.dns_regexes:
        for match in await scan.helpers.re.findall(dns_regex, to_search):
            matches.append(match)

    assert len(matches) == 8
    for s in subdomains:
        assert matches.count(s) == 2

    # re.findall_multi
    dns_regexes = {r.pattern: r for r in scan.dns_regexes}
    matches = []
    async for regex_name, results in scan.helpers.re.findall_multi(dns_regexes, to_search):
        assert len(results) == 2
        matches.extend(results)
    assert len(matches) == 8
    for s in subdomains:
        assert matches.count(s) == 2

    await scan._cleanup()

    # test yara hostname extractor helper
    scan = Scanner("evilcorp.com", "www.evilcorp.net", "evilcorp.co.uk")
    host_blob = """
    https://evilcorp.com/
    https://asdf.evilcorp.com/
    https://asdf.www.evilcorp.net/
    https://asdf.www.evilcorp.co.uk/
    https://asdf.www.evilcorp.com/
    https://asdf.www.evilcorp.com/
    https://test.api.www.evilcorp.net/
    """
    extracted = await scan.extract_in_scope_hostnames(host_blob)
    assert extracted == {
        "evilcorp.co.uk",
        "evilcorp.com",
        "www.evilcorp.com",
        "asdf.evilcorp.com",
        "asdf.www.evilcorp.com",
        "www.evilcorp.net",
        "api.www.evilcorp.net",
        "asdf.www.evilcorp.net",
        "test.api.www.evilcorp.net",
        "asdf.www.evilcorp.co.uk",
        "www.evilcorp.co.uk",
    }

    scan = Scanner()
    extracted = await scan.extract_in_scope_hostnames(host_blob)
    assert extracted == set()
