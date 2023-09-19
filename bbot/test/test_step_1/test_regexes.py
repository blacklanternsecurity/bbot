import pytest
import traceback

from bbot.core.event.helpers import get_event_type
from bbot.core.helpers import regexes
from bbot.core.errors import ValidationError


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
        matches = list(r.match(dns) for r in dns_name_regexes)
        assert any(matches), f"Good DNS_NAME {dns} did not match regexes"
        event_type, _ = get_event_type(dns)
        if not event_type == "DNS_NAME":
            assert (
                dns == "1.2.3.4" and event_type == "IP_ADDRESS"
            ), f"Event type for DNS_NAME {dns} was not properly detected"


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
        matches = list(r.match(open_port) for r in open_port_regexes)
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
        "http://evilcorp.",
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
        "evilcorp.com/path" "asdfasdfasdfasdfgsdgasdfs.asdfasdfasdfasdfasdf.evilcorp.com/path",
        "rhttps://evilcorp.com",
        "https://[e]",
        "https://[1]:80",
    ]

    good_urls = [
        "https://evilcorp.com",
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
        matches = list(r.match(good_url) for r in url_regexes)
        assert any(matches), f"Good URL {good_url} did not match regexes"
        assert (
            get_event_type(good_url)[0] == "URL_UNVERIFIED"
        ), f"Event type for URL {good_url} was not properly detected"
