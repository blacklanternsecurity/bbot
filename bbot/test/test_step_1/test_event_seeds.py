import pytest
import ipaddress
from bbot.errors import ValidationError
from bbot.core.event.helpers import EventSeed


def test_event_seeds():
    # DNS_NAME
    dns_seed = EventSeed("evilcOrp.com.")
    assert dns_seed.type == "DNS_NAME"
    assert dns_seed.data == "evilcorp.com"
    assert dns_seed.host == "evilcorp.com"
    assert dns_seed.input == "evilcorp.com"
    assert dns_seed._target_type == "TARGET"

    # IP_ADDRESS (IPv4)
    ipv4_seed = EventSeed("192.168.1.1")
    assert ipv4_seed.type == "IP_ADDRESS"
    assert ipv4_seed.data == "192.168.1.1"
    assert ipv4_seed.host == ipaddress.ip_address("192.168.1.1")
    assert ipv4_seed.input == "192.168.1.1"

    # Test various IPv6 formats
    ipv6_formats = [
        "2001:db8::ff00:42:8329",  # Standard format
        "2001:0db8:0000:0000:0000:ff00:0042:8329",  # Full format
        "2001:db8:0:0:0:ff00:42:8329",  # Mixed format
        "::1",  # Loopback
        "::ffff:192.168.1.1",  # IPv4-mapped
        "2001:db8::",  # Subnet prefix
        "fe80::1ff:fe23:4567:890a",  # Link-local
    ]

    # IP_ADDRESS (IPv6)
    for ipv6 in ipv6_formats:
        ipv6_seed = EventSeed(ipv6)
        normalized_ipv6 = str(ipaddress.IPv6Address(ipv6))
        assert ipv6_seed.type == "IP_ADDRESS"
        assert ipv6_seed.data == normalized_ipv6
        assert ipv6_seed.host == ipaddress.ip_address(ipv6)
        assert ipv6_seed.input == normalized_ipv6

    # IP_RANGE (IPv4)
    ipv4_range_seed = EventSeed("192.168.1.1/24")
    assert ipv4_range_seed.type == "IP_RANGE"
    assert ipv4_range_seed.data == "192.168.1.0/24"
    assert ipv4_range_seed.host == ipaddress.ip_network("192.168.1.0/24")
    assert ipv4_range_seed.input == "192.168.1.0/24"

    # IP_RANGE (IPv6)
    ipv6_range_seed = EventSeed("2001:db8::ff00:42:8329/64")
    assert ipv6_range_seed.type == "IP_RANGE"
    assert ipv6_range_seed.data == "2001:db8::/64"
    assert ipv6_range_seed.host == ipaddress.ip_network("2001:db8::/64")
    assert ipv6_range_seed.input == "2001:db8::/64"

    # OPEN_TCP_PORT (DNS)
    open_port_dns_seed = EventSeed("evilcOrp.com:80")
    assert open_port_dns_seed.type == "OPEN_TCP_PORT"
    assert open_port_dns_seed.data == "evilcorp.com:80"
    assert open_port_dns_seed.host == "evilcorp.com"
    assert open_port_dns_seed.port == 80
    assert open_port_dns_seed.input == "evilcorp.com:80"

    # OPEN_TCP_PORT (IPv4)
    open_port_ipv4_seed = EventSeed("192.168.1.1:80")
    assert open_port_ipv4_seed.type == "OPEN_TCP_PORT"
    assert open_port_ipv4_seed.data == "192.168.1.1:80"
    assert open_port_ipv4_seed.host == ipaddress.ip_address("192.168.1.1")
    assert open_port_ipv4_seed.port == 80
    assert open_port_ipv4_seed.input == "192.168.1.1:80"

    # OPEN_TCP_PORT (IPv6)
    open_port_ipv6_seed = EventSeed("[2001:db8::42]:80")
    assert open_port_ipv6_seed.type == "OPEN_TCP_PORT"
    assert open_port_ipv6_seed.data == "[2001:db8::42]:80"
    assert open_port_ipv6_seed.host == ipaddress.ip_address("2001:db8::42")
    assert open_port_ipv6_seed.port == 80
    assert open_port_ipv6_seed.input == "[2001:db8::42]:80"

    # URL (DNS_NAME)
    url_dns_seed = EventSeed("http://evilcOrp.com./index.html?a=b#c")
    assert url_dns_seed.type == "URL_UNVERIFIED"
    assert url_dns_seed.data == "http://evilcorp.com/index.html?a=b"
    assert url_dns_seed.host == "evilcorp.com"
    assert url_dns_seed.port == 80
    assert url_dns_seed.input == "http://evilcorp.com/index.html?a=b"

    # URL (IPv4)
    url_ipv4_seed = EventSeed("https://192.168.1.1/index.html?a=b#c")
    assert url_ipv4_seed.type == "URL_UNVERIFIED"
    assert url_ipv4_seed.data == "https://192.168.1.1/index.html?a=b"
    assert url_ipv4_seed.host == ipaddress.ip_address("192.168.1.1")
    assert url_ipv4_seed.port == 443
    assert url_ipv4_seed.input == "https://192.168.1.1/index.html?a=b"

    # URL (IPv6)
    url_ipv6_seed = EventSeed("https://[2001:db8::42]:8080/index.html?a=b#c")
    assert url_ipv6_seed.type == "URL_UNVERIFIED"
    assert url_ipv6_seed.data == "https://[2001:db8::42]:8080/index.html?a=b"
    assert url_ipv6_seed.host == ipaddress.ip_address("2001:db8::42")
    assert url_ipv6_seed.port == 8080
    assert url_ipv6_seed.input == "https://[2001:db8::42]:8080/index.html?a=b"

    # EMAIL_ADDRESS
    email_seed = EventSeed("john.doe@evilcOrp.com")
    assert email_seed.type == "EMAIL_ADDRESS"
    assert email_seed.data == "john.doe@evilcorp.com"
    assert email_seed.host == "evilcorp.com"
    assert email_seed.port == None
    assert email_seed.input == "john.doe@evilcorp.com"

    email_seed_ipv4 = EventSeed("john.doe@192.168.1.1:80")
    assert email_seed_ipv4.type == "EMAIL_ADDRESS"
    assert email_seed_ipv4.data == "john.doe@192.168.1.1:80"
    assert email_seed_ipv4.host == ipaddress.ip_address("192.168.1.1")
    assert email_seed_ipv4.port == 80
    assert email_seed_ipv4.input == "john.doe@192.168.1.1:80"

    # ORG_STUB
    org_stub_seed = EventSeed("ORG:evilcorp")
    assert org_stub_seed.type == "ORG_STUB"
    assert org_stub_seed.data == "evilcorp"
    assert org_stub_seed.host == None
    assert org_stub_seed.input == "ORG_STUB:evilcorp"

    # USERNAME
    username_seed = EventSeed("USER:john.doe")
    assert username_seed.type == "USERNAME"
    assert username_seed.data == "john.doe"
    assert username_seed.host == None
    assert username_seed.input == "USERNAME:john.doe"

    # FILESYSTEM
    filesystem_seed = EventSeed("FILE:/home/john/documents")
    assert filesystem_seed.type == "FILESYSTEM"
    assert filesystem_seed.data == {"path": "/home/john/documents"}
    assert filesystem_seed.host == None
    assert filesystem_seed.input == "FILESYSTEM:/home/john/documents"

    # MOBILE_APP
    mobile_app_seed = EventSeed("APK:https://play.google.com/store/apps/details?id=com.evilcorp.app")
    assert mobile_app_seed.type == "MOBILE_APP"
    assert mobile_app_seed.data == {"url": "https://play.google.com/store/apps/details?id=com.evilcorp.app"}
    assert mobile_app_seed.host == None
    assert mobile_app_seed.input == "MOBILE_APP:https://play.google.com/store/apps/details?id=com.evilcorp.app"

    with pytest.raises(ValidationError):
        EventSeed("INVALID:INVALID")

    with pytest.raises(ValidationError):
        EventSeed("^@#$^@#$")

    # BLACKLIST_REGEX
    blacklist_regex_seed = EventSeed("RE:evil[0-9]{3}")
    assert blacklist_regex_seed.type == "BLACKLIST_REGEX"
    assert blacklist_regex_seed.data == "evil[0-9]{3}"
    assert blacklist_regex_seed.host == None
    assert blacklist_regex_seed.input == "REGEX:evil[0-9]{3}"
    assert blacklist_regex_seed._target_type == "BLACKLIST"
