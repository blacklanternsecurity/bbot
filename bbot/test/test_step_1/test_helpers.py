import os
import sys
import time
import asyncio
import datetime
import ipaddress

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_helpers_misc(helpers, scan, bbot_scanner, bbot_httpserver):
    ### URL ###
    bad_urls = (
        "http://e.co/index.html",
        "http://e.co/u/1111/info",
        "http://e.co/u/2222/info",
        "http://e.co/u/3333/info",
        "http://e.co/u/4444/info",
        "http://e.co/u/5555/info",
    )
    new_urls = tuple(helpers.validators.collapse_urls(bad_urls, threshold=4))
    assert len(new_urls) == 2
    new_urls = tuple(sorted([u.geturl() for u in helpers.validators.collapse_urls(bad_urls, threshold=5)]))
    assert new_urls == bad_urls

    new_url = helpers.add_get_params("http://evilcorp.com/a?p=1&q=2", {"r": 3, "s": "asdf"}).geturl()
    query = dict(s.split("=") for s in new_url.split("?")[-1].split("&"))
    query = tuple(sorted(query.items(), key=lambda x: x[0]))
    assert query == (
        ("p", "1"),
        ("q", "2"),
        ("r", "3"),
        ("s", "asdf"),
    )
    assert tuple(sorted(helpers.get_get_params("http://evilcorp.com/a?p=1&q=2#frag").items())) == (
        ("p", ["1"]),
        ("q", ["2"]),
    )

    assert helpers.validators.clean_url("http://evilcorp.com:80").geturl() == "http://evilcorp.com/"
    assert helpers.validators.clean_url("http://evilcorp.com/asdf?a=asdf#frag").geturl() == "http://evilcorp.com/asdf"
    assert helpers.validators.clean_url("http://evilcorp.com//asdf").geturl() == "http://evilcorp.com/asdf"
    assert helpers.validators.clean_url("http://evilcorp.com.").geturl() == "http://evilcorp.com/"
    with pytest.raises(ValueError):
        helpers.validators.clean_url("http://evilcorp,com")

    assert helpers.url_depth("http://evilcorp.com/asdf/user/") == 2
    assert helpers.url_depth("http://evilcorp.com/asdf/user") == 2
    assert helpers.url_depth("http://evilcorp.com/asdf/") == 1
    assert helpers.url_depth("http://evilcorp.com/asdf") == 1
    assert helpers.url_depth("http://evilcorp.com/") == 0
    assert helpers.url_depth("http://evilcorp.com") == 0

    assert helpers.parent_url("http://evilcorp.com/subdir1/subdir2?foo=bar") == "http://evilcorp.com/subdir1"

    ### MISC ###
    assert helpers.is_domain("evilcorp.co.uk")
    assert not helpers.is_domain("www.evilcorp.co.uk")
    assert helpers.is_domain("evilcorp.notreal")
    assert not helpers.is_domain("asdf.evilcorp.notreal")
    assert not helpers.is_domain("notreal")
    assert helpers.is_subdomain("www.evilcorp.co.uk")
    assert not helpers.is_subdomain("evilcorp.co.uk")
    assert helpers.is_subdomain("www.evilcorp.notreal")
    assert not helpers.is_subdomain("evilcorp.notreal")
    assert not helpers.is_subdomain("notreal")
    assert helpers.is_url("http://evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert helpers.is_url("https://evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert helpers.is_uri("ftp://evilcorp.co.uk") is True
    assert helpers.is_uri("http://evilcorp.co.uk") is True
    assert helpers.is_uri("evilcorp.co.uk", return_scheme=True) == ""
    assert helpers.is_uri("ftp://evilcorp.co.uk", return_scheme=True) == "ftp"
    assert helpers.is_uri("FTP://evilcorp.co.uk", return_scheme=True) == "ftp"
    assert not helpers.is_url("https:/evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert not helpers.is_url("/evilcorp.co.uk/asdf?a=b&c=d#asdf")
    assert not helpers.is_url("ftp://evilcorp.co.uk")
    assert helpers.parent_domain("www.evilcorp.co.uk") == "evilcorp.co.uk"
    assert helpers.parent_domain("evilcorp.co.uk") == "evilcorp.co.uk"
    assert helpers.parent_domain("localhost") == "localhost"
    assert helpers.parent_domain("www.evilcorp.notreal") == "evilcorp.notreal"
    assert helpers.parent_domain("evilcorp.notreal") == "evilcorp.notreal"
    assert helpers.parent_domain("notreal") == "notreal"
    assert list(helpers.domain_parents("test.www.evilcorp.co.uk")) == ["www.evilcorp.co.uk", "evilcorp.co.uk"]
    assert list(helpers.domain_parents("www.evilcorp.co.uk", include_self=True)) == [
        "www.evilcorp.co.uk",
        "evilcorp.co.uk",
    ]
    assert list(helpers.domain_parents("evilcorp.co.uk", include_self=True)) == ["evilcorp.co.uk"]
    assert list(helpers.ip_network_parents("0.0.0.0/2")) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert list(helpers.ip_network_parents("0.0.0.0/1", include_self=True)) == [
        ipaddress.ip_network("0.0.0.0/1"),
        ipaddress.ip_network("0.0.0.0/0"),
    ]
    assert helpers.is_ip("127.0.0.1")
    assert helpers.is_ip("127.0.0.1", include_network=True)
    assert helpers.is_ip("127.0.0.1", version=4)
    assert not helpers.is_ip("127.0.0.1", version=6)
    assert not helpers.is_ip("127.0.0.0.1")

    assert helpers.is_ip("dead::beef")
    assert helpers.is_ip("dead::beef", include_network=True)
    assert not helpers.is_ip("dead::beef", version=4)
    assert helpers.is_ip("dead::beef", version=6)
    assert not helpers.is_ip("dead:::beef")

    assert not helpers.is_ip("1.2.3.4/24")
    assert helpers.is_ip("1.2.3.4/24", include_network=True)
    assert not helpers.is_ip("1.2.3.4/24", version=4)
    assert helpers.is_ip("1.2.3.4/24", include_network=True, version=4)
    assert not helpers.is_ip("1.2.3.4/24", include_network=True, version=6)

    assert not helpers.is_ip_type("127.0.0.1")
    assert helpers.is_ip_type(ipaddress.ip_address("127.0.0.1"))
    assert not helpers.is_ip_type(ipaddress.ip_address("127.0.0.1"), network=True)
    assert helpers.is_ip_type(ipaddress.ip_address("127.0.0.1"), network=False)
    assert helpers.is_ip_type(ipaddress.ip_network("127.0.0.0/8"))
    assert helpers.is_ip_type(ipaddress.ip_network("127.0.0.0/8"), network=True)
    assert not helpers.is_ip_type(ipaddress.ip_network("127.0.0.0/8"), network=False)

    assert helpers.is_dns_name("evilcorp.com")
    assert not helpers.is_dns_name("evilcorp.com:80")
    assert not helpers.is_dns_name("http://evilcorp.com:80")
    assert helpers.is_dns_name("evilcorp")
    assert helpers.is_dns_name("evilcorp.")
    assert helpers.is_dns_name("ドメイン.テスト")
    assert not helpers.is_dns_name("127.0.0.1")
    assert not helpers.is_dns_name("dead::beef")
    assert not helpers.is_dns_name("bob@evilcorp.com")

    assert helpers.domain_stem("evilcorp.co.uk") == "evilcorp"
    assert helpers.domain_stem("www.evilcorp.co.uk") == "www.evilcorp"

    assert tuple(await helpers.re.extract_emails("asdf@asdf.com\nT@t.Com&a=a@a.com__ b@b.com")) == (
        "asdf@asdf.com",
        "t@t.com",
        "a@a.com",
        "b@b.com",
    )

    assert helpers.extract_host("evilcorp.com:80") == ("evilcorp.com", "", ":80")
    assert helpers.extract_host("http://evilcorp.com:80/asdf.php?a=b") == (
        "evilcorp.com",
        "http://",
        ":80/asdf.php?a=b",
    )
    assert helpers.extract_host("http://evilcorp.com:80/asdf.php?a=b@a.com") == (
        "evilcorp.com",
        "http://",
        ":80/asdf.php?a=b@a.com",
    )
    assert helpers.extract_host("bob@evilcorp.com") == ("evilcorp.com", "bob@", "")
    assert helpers.extract_host("[dead::beef]:22") == ("dead::beef", "[", "]:22")
    assert helpers.extract_host("scp://[dead::beef]:22") == ("dead::beef", "scp://[", "]:22")
    assert helpers.extract_host("https://[dead::beef]:22?a=b") == ("dead::beef", "https://[", "]:22?a=b")
    assert helpers.extract_host("https://[dead::beef]/?a=b") == ("dead::beef", "https://[", "]/?a=b")
    assert helpers.extract_host("https://[dead::beef]?a=b") == ("dead::beef", "https://[", "]?a=b")
    assert helpers.extract_host("https://[::1]") == ("::1", "https://[", "]")
    assert helpers.extract_host("ftp://username:password@my-ftp.com/my-file.csv") == (
        "my-ftp.com",
        "ftp://username:password@",
        "/my-file.csv",
    )
    assert helpers.extract_host("ftp://username:p@ssword@my-ftp.com/my-file.csv") == (
        "my-ftp.com",
        "ftp://username:p@ssword@",
        "/my-file.csv",
    )
    assert helpers.extract_host("ftp://username:password:/@my-ftp.com/my-file.csv") == (
        "my-ftp.com",
        "ftp://username:password:/@",
        "/my-file.csv",
    )
    assert helpers.extract_host("ftp://username:password:/@dead::beef/my-file.csv") == (
        None,
        "ftp://username:password:/@dead::beef/my-file.csv",
        "",
    )
    assert helpers.extract_host("ftp://username:password:/@[dead::beef]/my-file.csv") == (
        "dead::beef",
        "ftp://username:password:/@[",
        "]/my-file.csv",
    )
    assert helpers.extract_host("ftp://username:password:/@[dead::beef]:22/my-file.csv") == (
        "dead::beef",
        "ftp://username:password:/@[",
        "]:22/my-file.csv",
    )

    assert helpers.best_http_status(200, 404) == 200
    assert helpers.best_http_status(500, 400) == 400
    assert helpers.best_http_status(301, 302) == 301
    assert helpers.best_http_status(0, 302) == 302
    assert helpers.best_http_status(500, 0) == 500

    assert helpers.split_domain("www.evilcorp.co.uk") == ("www", "evilcorp.co.uk")
    assert helpers.split_domain("asdf.www.test.notreal") == ("asdf.www", "test.notreal")
    assert helpers.split_domain("www.test.notreal") == ("www", "test.notreal")
    assert helpers.split_domain("test.notreal") == ("", "test.notreal")
    assert helpers.split_domain("notreal") == ("", "notreal")
    assert helpers.split_domain("192.168.0.1") == ("", "192.168.0.1")
    assert helpers.split_domain("dead::beef") == ("", "dead::beef")

    assert helpers.subdomain_depth("a.s.d.f.evilcorp.co.uk") == 4
    assert helpers.subdomain_depth("a.s.d.f.evilcorp.com") == 4
    assert helpers.subdomain_depth("evilcorp.com") == 0
    assert helpers.subdomain_depth("a.evilcorp.com") == 1
    assert helpers.subdomain_depth("a.s.d.f.evilcorp.notreal") == 4

    assert helpers.split_host_port("http://evilcorp.co.uk") == ("evilcorp.co.uk", 80)
    assert helpers.split_host_port("https://evilcorp.co.uk") == ("evilcorp.co.uk", 443)
    assert helpers.split_host_port("ws://evilcorp.co.uk") == ("evilcorp.co.uk", 80)
    assert helpers.split_host_port("wss://evilcorp.co.uk") == ("evilcorp.co.uk", 443)
    assert helpers.split_host_port("WSS://evilcorp.co.uk") == ("evilcorp.co.uk", 443)
    assert helpers.split_host_port("http://evilcorp.co.uk:666") == ("evilcorp.co.uk", 666)
    assert helpers.split_host_port("evilcorp.co.uk:666") == ("evilcorp.co.uk", 666)
    assert helpers.split_host_port("evilcorp.co.uk") == ("evilcorp.co.uk", None)
    assert helpers.split_host_port("192.168.0.1") == (ipaddress.ip_address("192.168.0.1"), None)
    assert helpers.split_host_port("192.168.0.1:80") == (ipaddress.ip_address("192.168.0.1"), 80)
    assert helpers.split_host_port("[e]:80") == ("e", 80)
    assert helpers.split_host_port("d://wat:wat") == ("wat", None)
    assert helpers.split_host_port("https://[dead::beef]:8338") == (ipaddress.ip_address("dead::beef"), 8338)
    assert helpers.split_host_port("[dead::beef]") == (ipaddress.ip_address("dead::beef"), None)
    assert helpers.split_host_port("dead::beef") == (ipaddress.ip_address("dead::beef"), None)
    extracted_words = helpers.extract_words("blacklanternsecurity")
    assert "black" in extracted_words
    # assert "blacklantern" in extracted_words
    # assert "lanternsecurity" in extracted_words
    # assert "blacklanternsecurity" in extracted_words
    assert "bls" in extracted_words

    choices = ["asdf.fdsa", "asdf.1234", "4321.5678"]
    best_match = helpers.closest_match("asdf.123a", choices)
    assert best_match == "asdf.1234"
    best_matches = helpers.closest_match("asdf.123a", choices, n=2)
    assert len(best_matches) == 2
    assert best_matches[0] == "asdf.1234"
    assert best_matches[1] == "asdf.fdsa"

    ipv4_netloc = helpers.make_netloc("192.168.1.1", 80)
    assert ipv4_netloc == "192.168.1.1:80"
    assert helpers.make_netloc("192.168.1.1") == "192.168.1.1"
    assert helpers.make_netloc(ipaddress.ip_address("192.168.1.1"), None) == "192.168.1.1"
    assert helpers.make_netloc("dead::beef", "443") == "[dead::beef]:443"
    assert helpers.make_netloc(ipaddress.ip_address("dead::beef"), 443) == "[dead::beef]:443"
    assert helpers.make_netloc("dead::beef", None) == "[dead::beef]"
    assert helpers.make_netloc(ipaddress.ip_address("dead::beef"), None) == "[dead::beef]"

    assert helpers.get_file_extension("https://evilcorp.com/evilcorp.com/test/asdf.TXT") == "txt"
    assert helpers.get_file_extension("/etc/conf/test.tar.gz") == "gz"
    assert helpers.get_file_extension("/etc/passwd") == ""

    assert helpers.tagify("HttP  -_Web  Title--  ") == "http-web-title"
    tagged_event = scan.make_event("127.0.0.1", parent=scan.root_event, tags=["HttP  web -__- title  "])
    assert "http-web-title" in tagged_event.tags
    tagged_event.remove_tag("http-web-title")
    assert "http-web-title" not in tagged_event.tags
    tagged_event.add_tag("Another tag  ")
    assert "another-tag" in tagged_event.tags
    tagged_event.tags = ["Some other tag  "]
    assert isinstance(tagged_event._tags, set)
    assert "another-tag" not in tagged_event.tags
    assert "some-other-tag" in tagged_event.tags

    assert list(helpers.search_dict_by_key("asdf", {"asdf": "fdsa", 4: [{"asdf": 5}]})) == ["fdsa", 5]
    assert list(helpers.search_dict_by_key("asdf", {"wat": {"asdf": "fdsa"}})) == ["fdsa"]
    assert list(helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"asdf": "fdsa"}]}])) == ["fdsa"]
    assert not list(helpers.search_dict_by_key("asdf", [{"wat": {"nope": 1}}, {"wat": [{"fdsa": "asdf"}]}]))
    assert not list(helpers.search_dict_by_key("asdf", "asdf"))

    from bbot.core.helpers.regexes import url_regexes

    dict_to_search = {
        "key1": {
            "key2": [{"key3": "A url of some kind: https://www.evilcorp.com/asdf"}],
            "key4": "A url of some kind: https://www.evilcorp.com/fdsa",
        }
    }
    assert set(helpers.search_dict_values(dict_to_search, *url_regexes)) == {
        "https://www.evilcorp.com/asdf",
        "https://www.evilcorp.com/fdsa",
    }

    replaced = helpers.search_format_dict(
        {"asdf": [{"wat": {"here": "#{replaceme}!"}}, {500: True}]}, replaceme="asdf"
    )
    assert replaced["asdf"][1][500] is True
    assert replaced["asdf"][0]["wat"]["here"] == "asdf!"

    filtered_dict = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "api_key"
    )
    assert "api_key" in filtered_dict["modules"]["c99"]
    assert "filterme" not in filtered_dict["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict["modules"]

    filtered_dict2 = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "c99"
    )
    assert "api_key" in filtered_dict2["modules"]["c99"]
    assert "filterme" in filtered_dict2["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict2["modules"]

    filtered_dict3 = helpers.filter_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}},
        "key",
        fuzzy=True,
    )
    assert "api_key" in filtered_dict3["modules"]["c99"]
    assert "filterme" not in filtered_dict3["modules"]["c99"]
    assert "ipneighbor" not in filtered_dict3["modules"]

    filtered_dict4 = helpers.filter_dict(
        {"modules": {"secrets_db": {"api_key": "1234"}, "ipneighbor": {"secret": "test", "asdf": "1234"}}},
        "secret",
        fuzzy=True,
        exclude_keys="modules",
    )
    assert "secrets_db" not in filtered_dict4["modules"]
    assert "ipneighbor" in filtered_dict4["modules"]
    assert "secret" in filtered_dict4["modules"]["ipneighbor"]
    assert "asdf" not in filtered_dict4["modules"]["ipneighbor"]

    cleaned_dict = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "api_key"
    )
    assert "api_key" not in cleaned_dict["modules"]["c99"]
    assert "filterme" in cleaned_dict["modules"]["c99"]
    assert "ipneighbor" in cleaned_dict["modules"]

    cleaned_dict2 = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}}, "c99"
    )
    assert "c99" not in cleaned_dict2["modules"]
    assert "ipneighbor" in cleaned_dict2["modules"]

    cleaned_dict3 = helpers.clean_dict(
        {"modules": {"c99": {"api_key": "1234", "filterme": "asdf"}, "ipneighbor": {"test": "test"}}},
        "key",
        fuzzy=True,
    )
    assert "api_key" not in cleaned_dict3["modules"]["c99"]
    assert "filterme" in cleaned_dict3["modules"]["c99"]
    assert "ipneighbor" in cleaned_dict3["modules"]

    cleaned_dict4 = helpers.clean_dict(
        {"modules": {"secrets_db": {"api_key": "1234"}, "ipneighbor": {"secret": "test", "asdf": "1234"}}},
        "secret",
        fuzzy=True,
        exclude_keys="modules",
    )
    assert "secrets_db" in cleaned_dict4["modules"]
    assert "ipneighbor" in cleaned_dict4["modules"]
    assert "secret" not in cleaned_dict4["modules"]["ipneighbor"]
    assert "asdf" in cleaned_dict4["modules"]["ipneighbor"]

    assert helpers.split_list([1, 2, 3, 4, 5]) == [[1, 2], [3, 4, 5]]
    assert list(helpers.grouper("ABCDEFG", 3)) == [["A", "B", "C"], ["D", "E", "F"], ["G"]]

    assert len(helpers.rand_string(3)) == 3
    assert len(helpers.rand_string(1)) == 1
    assert len(helpers.rand_string(0)) == 0
    assert type(helpers.rand_string(0)) == str

    test_file = Path(scan.config["home"]) / "testfile.asdf"
    test_file.touch()

    assert test_file.is_file()
    backup = helpers.backup_file(test_file)
    assert backup.name == "testfile.1.asdf"
    assert not test_file.exists()
    assert backup.is_file()
    test_file.touch()
    backup2 = helpers.backup_file(test_file)
    assert backup2.name == "testfile.1.asdf"
    assert not test_file.exists()
    assert backup2.is_file()
    older_backup = Path(scan.config["home"]) / "testfile.2.asdf"
    assert older_backup.is_file()
    older_backup.unlink()
    backup.unlink()

    with open(test_file, "w") as f:
        f.write("asdf\nfdsa")

    assert "asdf" in helpers.str_or_file(str(test_file))
    assert "nope" in helpers.str_or_file("nope")
    assert tuple(helpers.chain_lists([str(test_file), "nope"], try_files=True)) == ("asdf", "fdsa", "nope")
    assert tuple(helpers.chain_lists("one, two", try_files=True)) == ("one", "two")
    assert tuple(helpers.chain_lists("one, two three ,four five")) == ("one", "two", "three", "four", "five")
    assert test_file.is_file()

    with pytest.raises(DirectoryCreationError, match="Failed to create.*"):
        helpers.mkdir(test_file)

    helpers.delete_file(test_file)
    assert not test_file.exists()

    timedelta = datetime.timedelta(hours=1, minutes=2, seconds=3)
    assert helpers.human_timedelta(timedelta) == "1 hour, 2 minutes, 3 seconds"
    timedelta = datetime.timedelta(hours=3, seconds=1)
    assert helpers.human_timedelta(timedelta) == "3 hours, 1 second"
    timedelta = datetime.timedelta(seconds=2)
    assert helpers.human_timedelta(timedelta) == "2 seconds"

    ### VALIDATORS ###
    # hosts
    assert helpers.validators.validate_host(" evilCorp.COM.") == "evilcorp.com"
    assert helpers.validators.validate_host("LOCALHOST ") == "localhost"
    assert helpers.validators.validate_host(" 192.168.1.1") == "192.168.1.1"
    assert helpers.validators.validate_host(" Dead::c0dE ") == "dead::c0de"
    assert helpers.validators.validate_host(".*.wildcard.evilcorp.com") == "wildcard.evilcorp.com"
    assert helpers.validators.soft_validate(" evilCorp.COM", "host") is True
    assert helpers.validators.soft_validate("!@#$", "host") is False
    with pytest.raises(ValueError):
        assert helpers.validators.validate_host("!@#$")
    # ports
    assert helpers.validators.validate_port(666) == 666
    assert helpers.validators.validate_port(666666) == 65535
    assert helpers.validators.soft_validate(666, "port") is True
    assert helpers.validators.soft_validate("!@#$", "port") is False
    with pytest.raises(ValueError):
        helpers.validators.validate_port("asdf")
    # top tcp ports
    top_tcp_ports = helpers.top_tcp_ports(100)
    assert len(top_tcp_ports) == 100
    assert len(set(top_tcp_ports)) == 100
    top_tcp_ports = helpers.top_tcp_ports(800000)
    assert top_tcp_ports[:10] == [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]
    assert top_tcp_ports[-10:] == [65526, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
    assert len(top_tcp_ports) == 65535
    assert len(set(top_tcp_ports)) == 65535
    assert all(isinstance(i, int) for i in top_tcp_ports)
    top_tcp_ports = helpers.top_tcp_ports(10, as_string=True)
    assert top_tcp_ports == "80,23,443,21,22,25,3389,110,445,139"
    # urls
    assert helpers.validators.validate_url(" httP://evilcorP.com/asdf?a=b&c=d#e") == "http://evilcorp.com/asdf"
    assert (
        helpers.validators.validate_url_parsed(" httP://evilcorP.com/asdf?a=b&c=d#e").geturl()
        == "http://evilcorp.com/asdf"
    )
    assert helpers.validators.soft_validate(" httP://evilcorP.com/asdf?a=b&c=d#e", "url") is True
    assert helpers.validators.soft_validate("!@#$", "url") is False
    with pytest.raises(ValueError):
        helpers.validators.validate_url("!@#$")
    # severities
    assert helpers.validators.validate_severity(" iNfo") == "INFO"
    assert helpers.validators.soft_validate(" iNfo", "severity") is True
    assert helpers.validators.soft_validate("NOPE", "severity") is False
    with pytest.raises(ValueError):
        helpers.validators.validate_severity("NOPE")
    # emails
    assert helpers.validators.validate_email(" bOb@eViLcorp.COM") == "bob@evilcorp.com"
    assert helpers.validators.soft_validate(" bOb@eViLcorp.COM", "email") is True
    assert helpers.validators.soft_validate("!@#$", "email") is False
    with pytest.raises(ValueError):
        helpers.validators.validate_email("!@#$")

    assert type(helpers.make_date()) == str

    # string formatter
    s = "asdf {unused} {used}"
    assert helpers.safe_format(s, used="fdsa") == "asdf {unused} fdsa"

    # is_printable
    assert helpers.is_printable("asdf") is True
    assert helpers.is_printable(r"""~!@#$^&*()_+=-<>:"?,./;'[]\{}|""") is True
    assert helpers.is_printable("ドメイン.テスト") is True
    assert helpers.is_printable("4") is True
    assert helpers.is_printable("asdf\x00") is False

    # punycode
    assert helpers.smart_encode_punycode("ドメイン.テスト") == "xn--eckwd4c7c.xn--zckzah"
    assert helpers.smart_decode_punycode("xn--eckwd4c7c.xn--zckzah") == "ドメイン.テスト"
    assert helpers.smart_encode_punycode("evilcorp.com") == "evilcorp.com"
    assert helpers.smart_decode_punycode("evilcorp.com") == "evilcorp.com"
    assert helpers.smart_encode_punycode("bob_smith@ドメイン.テスト") == "bob_smith@xn--eckwd4c7c.xn--zckzah"
    assert helpers.smart_decode_punycode("bob_smith@xn--eckwd4c7c.xn--zckzah") == "bob_smith@ドメイン.テスト"
    assert helpers.smart_encode_punycode("ドメイン.テスト:80") == "xn--eckwd4c7c.xn--zckzah:80"
    assert helpers.smart_decode_punycode("xn--eckwd4c7c.xn--zckzah:80") == "ドメイン.テスト:80"

    assert await helpers.re.recursive_decode("Hello%20world%21") == "Hello world!"
    assert (
        await helpers.re.recursive_decode("Hello%20%5Cu041f%5Cu0440%5Cu0438%5Cu0432%5Cu0435%5Cu0442") == "Hello Привет"
    )
    assert (
        await helpers.re.recursive_decode("%5Cu0020%5Cu041f%5Cu0440%5Cu0438%5Cu0432%5Cu0435%5Cu0442%5Cu0021")
        == " Привет!"
    )
    assert await helpers.re.recursive_decode("Hello%2520world%2521") == "Hello world!"
    assert (
        await helpers.re.recursive_decode(
            "Hello%255Cu0020%255Cu041f%255Cu0440%255Cu0438%255Cu0432%255Cu0435%255Cu0442"
        )
        == "Hello Привет"
    )
    assert (
        await helpers.re.recursive_decode(
            "%255Cu0020%255Cu041f%255Cu0440%255Cu0438%255Cu0432%255Cu0435%255Cu0442%255Cu0021"
        )
        == " Привет!"
    )
    assert (
        await helpers.re.recursive_decode(r"Hello\\nWorld\\\tGreetings\\\\nMore\nText")
        == "Hello\nWorld\tGreetings\nMore\nText"
    )

    ### CACHE ###
    helpers.cache_put("string", "wat")
    helpers.cache_put("binary", b"wat")
    assert helpers.cache_get("string") == "wat"
    assert helpers.cache_get("binary") == "wat"
    assert helpers.cache_get("binary", text=False) == b"wat"
    cache_filename = helpers.cache_filename("string")
    (m, i, d, n, u, g, sz, atime, mtime, ctime) = os.stat(str(cache_filename))
    # change modified time to be 10 days in the past
    os.utime(str(cache_filename), times=(atime, mtime - (3600 * 24 * 10)))
    assert helpers.cache_get("string", cache_hrs=24 * 7) is None
    assert helpers.cache_get("string", cache_hrs=24 * 14) == "wat"

    test_file = Path(scan.config["home"]) / "testfile.asdf"
    with open(test_file, "w") as f:
        for i in range(100):
            f.write(f"{i}\n")
    assert len(list(open(test_file).readlines())) == 100
    assert (await helpers.wordlist(test_file)).is_file()
    truncated_file = await helpers.wordlist(test_file, lines=10)
    assert truncated_file.is_file()
    assert len(list(open(truncated_file).readlines())) == 10
    with pytest.raises(WordlistError):
        await helpers.wordlist("/tmp/a9pseoysadf/asdkgjaosidf")
    test_file.unlink()

    # filename truncation
    super_long_filename = "/tmp/" + ("a" * 1024) + ".txt"
    with pytest.raises(OSError):
        with open(super_long_filename, "w") as f:
            f.write("wat")
    truncated_filename = helpers.truncate_filename(super_long_filename)
    with open(truncated_filename, "w") as f:
        f.write("wat")
    truncated_filename.unlink()

    # misc DNS helpers
    assert helpers.is_ptr("wsc-11-22-33-44-wat.evilcorp.com") is True
    assert helpers.is_ptr("wsc-11-22-33-wat.evilcorp.com") is False
    assert helpers.is_ptr("11wat.evilcorp.com") is False

    ## NTLM
    testheader = "TlRMTVNTUAACAAAAHgAeADgAAAAVgorilwL+bvnVipUAAAAAAAAAAJgAmABWAAAACgBjRQAAAA9XAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAACAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgAAQAeAFcASQBOAC0AUwA0ADIATgBPAEIARABWAFQASwA4AAQAHgBXAEkATgAtAFMANAAyAE4ATwBCAEQAVgBUAEsAOAADAB4AVwBJAE4ALQBTADQAMgBOAE8AQgBEAFYAVABLADgABwAIAHUwOZlfoNgBAAAAAA=="
    decoded = helpers.ntlm.ntlmdecode(testheader)
    assert decoded["NetBIOS_Domain_Name"] == "WIN-S42NOBDVTK8"
    assert decoded["NetBIOS_Computer_Name"] == "WIN-S42NOBDVTK8"
    assert decoded["DNS_Domain_name"] == "WIN-S42NOBDVTK8"
    assert decoded["FQDN"] == "WIN-S42NOBDVTK8"
    assert decoded["Timestamp"] == b"u09\x99_\xa0\xd8\x01"
    with pytest.raises(NTLMError):
        helpers.ntlm.ntlmdecode("asdf")

    test_filesize = bbot_test_dir / "test_filesize"
    test_filesize.touch()
    assert test_filesize.is_file()
    assert helpers.filesize(test_filesize) == 0
    assert helpers.filesize(bbot_test_dir / "glkasjdlgksadlkfsdf") == 0

    # memory stuff
    int(helpers.memory_status().available)
    int(helpers.swap_status().total)

    assert helpers.bytes_to_human(459819198709) == "428.24GB"
    assert helpers.human_to_bytes("428.24GB") == 459819198709

    # ordinals
    assert helpers.integer_to_ordinal(1) == "1st"
    assert helpers.integer_to_ordinal(2) == "2nd"
    assert helpers.integer_to_ordinal(3) == "3rd"
    assert helpers.integer_to_ordinal(4) == "4th"
    assert helpers.integer_to_ordinal(11) == "11th"
    assert helpers.integer_to_ordinal(12) == "12th"
    assert helpers.integer_to_ordinal(13) == "13th"
    assert helpers.integer_to_ordinal(21) == "21st"
    assert helpers.integer_to_ordinal(22) == "22nd"
    assert helpers.integer_to_ordinal(23) == "23rd"
    assert helpers.integer_to_ordinal(101) == "101st"
    assert helpers.integer_to_ordinal(111) == "111th"
    assert helpers.integer_to_ordinal(112) == "112th"
    assert helpers.integer_to_ordinal(113) == "113th"
    assert helpers.integer_to_ordinal(0) == "0th"

    await scan._cleanup()

    scan1 = bbot_scanner(modules="ipneighbor")
    await scan1._prep()
    assert int(helpers.get_size(scan1.modules["ipneighbor"])) > 0

    await scan1._cleanup()

    # weighted shuffle (used for module queues)
    items = ["a", "b", "c", "d", "e"]
    first_frequencies = {i: 0 for i in items}
    weights = [1, 2, 3, 4, 5]
    for i in range(10000):
        shuffled = helpers.weighted_shuffle(items, weights)
        first = shuffled[0]
        first_frequencies[first] += 1
    assert (
        first_frequencies["a"]
        < first_frequencies["b"]
        < first_frequencies["c"]
        < first_frequencies["d"]
        < first_frequencies["e"]
    )

    # error handling helpers
    test_ran = False
    try:
        try:
            raise KeyboardInterrupt("asdf")
        except KeyboardInterrupt:
            raise ValueError("asdf")
    except Exception as e:
        assert len(helpers.get_exception_chain(e)) == 2
        assert len([_ for _ in helpers.get_exception_chain(e) if isinstance(_, KeyboardInterrupt)]) == 1
        assert len([_ for _ in helpers.get_exception_chain(e) if isinstance(_, ValueError)]) == 1
        assert helpers.in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)) is True
        assert helpers.in_exception_chain(e, (TypeError, OSError)) is False
        test_ran = True
    assert test_ran
    test_ran = False
    try:
        try:
            raise AttributeError("asdf")
        except AttributeError:
            raise ValueError("asdf")
    except Exception as e:
        assert len(helpers.get_exception_chain(e)) == 2
        assert len([_ for _ in helpers.get_exception_chain(e) if isinstance(_, AttributeError)]) == 1
        assert len([_ for _ in helpers.get_exception_chain(e) if isinstance(_, ValueError)]) == 1
        assert helpers.in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)) is False
        assert helpers.in_exception_chain(e, (KeyboardInterrupt, AttributeError)) is True
        assert helpers.in_exception_chain(e, (AttributeError,)) is True
        test_ran = True
    assert test_ran


@pytest.mark.asyncio
async def test_word_cloud(helpers, bbot_scanner):
    number_mutations = helpers.word_cloud.get_number_mutations("base2_p013", n=5, padding=2)
    assert "base0_p013" in number_mutations
    assert "base7_p013" in number_mutations
    assert "base8_p013" not in number_mutations
    assert "base2_p008" in number_mutations
    assert "base2_p007" not in number_mutations
    assert "base2_p018" in number_mutations
    assert "base2_p0134" in number_mutations
    assert "base2_p0135" not in number_mutations

    permutations = helpers.word_cloud.mutations("_base", numbers=1)
    assert ("_base", "dev") in permutations
    assert ("dev", "_base") in permutations

    # saving and loading
    scan1 = bbot_scanner("127.0.0.1")
    await scan1._prep()
    word_cloud = scan1.helpers.word_cloud
    word_cloud.add_word("lantern")
    word_cloud.add_word("black")
    word_cloud.add_word("black")
    word_cloud.save()
    with open(word_cloud.default_filename) as f:
        word_cloud_content = [l.rstrip() for l in f.read().splitlines()]
    assert len(word_cloud_content) == 2
    assert "2\tblack" in word_cloud_content
    assert "1\tlantern" in word_cloud_content
    word_cloud.save(limit=1)
    with open(word_cloud.default_filename) as f:
        word_cloud_content = [l.rstrip() for l in f.read().splitlines()]
    assert len(word_cloud_content) == 1
    assert "2\tblack" in word_cloud_content
    assert "1\tlantern" not in word_cloud_content
    word_cloud.clear()
    with open(word_cloud.default_filename, "w") as f:
        f.write("plumbus\nrumbus")
    word_cloud.load()
    assert word_cloud["plumbus"] == 1
    assert word_cloud["rumbus"] == 1

    # mutators
    from bbot.core.helpers.wordcloud import DNSMutator

    m = DNSMutator()
    m.add_word("blacklantern-security237")
    mutations = set(m)
    assert mutations == {
        (None,),
        (None, "237"),
        (None, "-security237"),
        (None, "lanternsecurity237"),
        (None, "lantern-security237"),
        ("blacklantern-", None),
        ("blacklantern", None, "237"),
        ("blacklantern-", None, "237"),
        ("black", None, "security237"),
        ("black", None, "-security237"),
    }

    m = DNSMutator()
    m.add_word("blacklantern-security")
    m.add_word("sec")
    m.add_word("sec2")
    m.add_word("black2")
    mutations = sorted(m.mutations("whitebasket"))
    assert mutations == sorted(
        [
            "basket",
            "basket-security",
            "basket2",
            "basketlantern-security",
            "basketlanternsecurity",
            "blackbasket-security",
            "blackbasketsecurity",
            "blacklantern-basket",
            "blacklantern-white",
            "blacklantern-whitebasket",
            "blacklanternbasket",
            "blacklanternwhite",
            "blacklanternwhitebasket",
            "blackwhite-security",
            "blackwhitebasket-security",
            "blackwhitebasketsecurity",
            "blackwhitesecurity",
            "white",
            "white-security",
            "white2",
            "whitebasket",
            "whitebasket-security",
            "whitebasket2",
            "whitebasketlantern-security",
            "whitebasketlanternsecurity",
            "whitelantern-security",
            "whitelanternsecurity",
        ]
    )
    top_mutations = sorted(m.top_mutations().items(), key=lambda x: x[-1], reverse=True)
    assert top_mutations[:2] == [((None,), 4), ((None, "2"), 2)]

    await scan1._cleanup()


def test_names(helpers):
    assert helpers.names == sorted(helpers.names)
    assert helpers.adjectives == sorted(helpers.adjectives)


@pytest.mark.asyncio
async def test_ratelimiter(helpers):
    from bbot.core.helpers.ratelimiter import RateLimiter

    results = []

    async def web_request(r):
        async with r:
            await asyncio.sleep(0.12345)
            results.append(None)

    # allow 10 requests per second
    r = RateLimiter(10, "Test")
    tasks = []
    # start 500 requests
    for i in range(500):
        tasks.append(asyncio.create_task(web_request(r)))
    # sleep for 5 seconds
    await asyncio.sleep(5)
    await helpers.cancel_tasks(tasks)
    # 5 seconds * 10 requests per second == 50
    assert 45 <= len(results) <= 55


def test_sync_to_async():
    from bbot.core.helpers.async_helpers import async_to_sync_gen

    # async to sync generator converter
    async def async_gen():
        for i in range(5):
            await asyncio.sleep(0.1)
            yield i

    sync_gen = async_to_sync_gen(async_gen())

    l = []
    while 1:
        try:
            l.append(next(sync_gen))
        except StopIteration:
            break
    assert l == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_async_helpers():
    import random
    from bbot.core.helpers.misc import as_completed

    async def do_stuff(r):
        await asyncio.sleep(r)
        return r

    random_ints = [random.random() for _ in range(1000)]
    tasks = [do_stuff(r) for r in random_ints]
    results = set()
    async for t in as_completed(tasks):
        results.add(await t)
    assert len(results) == 1000
    assert sorted(random_ints) == sorted(results)


def test_portparse(helpers):
    assert helpers.parse_port_string("80,443,22") == [80, 443, 22]
    assert helpers.parse_port_string(80) == [80]

    assert helpers.parse_port_string("80,443,22,1000-1002") == [80, 443, 22, 1000, 1001, 1002]

    with pytest.raises(ValueError) as e:
        helpers.parse_port_string("80,443,22,70000")
    assert str(e.value) == "Invalid port: 70000"

    with pytest.raises(ValueError) as e:
        helpers.parse_port_string("80,443,22,1000-70000")
    assert str(e.value) == "Invalid port range: 1000-70000"

    with pytest.raises(ValueError) as e:
        helpers.parse_port_string("80,443,22,1000-1001-1002")
    assert str(e.value) == "Invalid port or port range: 1000-1001-1002"

    with pytest.raises(ValueError) as e:
        helpers.parse_port_string("80,443,22,1002-1000")
    assert str(e.value) == "Invalid port range: 1002-1000"

    with pytest.raises(ValueError) as e:
        helpers.parse_port_string("80,443,22,foo")
    assert str(e.value) == "Invalid port or port range: foo"


# test chain_lists helper


def test_liststring_valid_strings(helpers):
    assert helpers.chain_lists("hello,world,bbot") == ["hello", "world", "bbot"]


def test_liststring_invalid_string(helpers):
    with pytest.raises(ValueError) as e:
        helpers.chain_lists("hello,world,\x01", validate=True)
    assert str(e.value) == "Invalid character in string: \x01"


def test_liststring_singleitem(helpers):
    assert helpers.chain_lists("hello") == ["hello"]


def test_liststring_invalidfnchars(helpers):
    with pytest.raises(ValueError) as e:
        helpers.chain_lists("hello,world,bbot|test", validate=True)
    assert str(e.value) == "Invalid character in string: bbot|test"


# test parameter validation
@pytest.mark.asyncio
async def test_parameter_validation(helpers):
    getparam_valid_params = {
        "name",
        "age",
        "valid_name",
        "valid-name",
        "session_token",
        "user.id",
        "user-name",
        "client.id",
        "auth-token",
        "access_token",
        "abcd",
        "jqueryget",
        "<script>",
    }
    getparam_invalid_params = {
        "invalid,name",
        "###$$$",
        "this_parameter_name_is_seriously_way_too_long_to_be_practical_but_hey_look_its_still_technically_valid_wow",
        "parens()",
        "cookie$name",
    }

    getparam_params = getparam_valid_params | getparam_invalid_params
    for p in getparam_params:
        if helpers.validate_parameter(p, "getparam"):
            assert p in getparam_valid_params and p not in getparam_invalid_params
        else:
            assert p in getparam_invalid_params and p not in getparam_valid_params

    header_valid_params = {
        "name",
        "age",
        "valid_name",
        "valid-name",
        "session_token",
        "user-name",
        "auth-token",
        "access_token",
        "abcd",
        "jqueryget",
    }
    header_invalid_params = {
        "invalid,name",
        "<script>",
        "this_parameter_name_is_seriously_way_too_long_to_be_practical_but_hey_look_its_still_technically_valid_wow",
        "parens()",
        "cookie$name",
        "carrot^",
        "###$$$",
        "user.id",
        "client.id",
    }

    header_params = header_valid_params | header_invalid_params
    for p in header_params:
        if helpers.validate_parameter(p, "header"):
            assert p in header_valid_params and p not in header_invalid_params
        else:
            assert p in header_invalid_params and p not in header_valid_params

    cookie_valid_params = {
        "name",
        "age",
        "valid_name",
        "valid-name",
        "session_token",
        "user-name",
        "auth-token",
        "access_token",
        "user.id",
        "client.id",
        "abcd",
        "jqueryget",
        "###$$$",
        "cookie$name",
    }
    cookie_invalid_params = {
        "invalid,name",
        "<script>",
        "parens()",
        "this_parameter_name_is_seriously_way_too_long_to_be_practical_but_hey_look_its_still_technically_valid_wow",
    }

    cookie_params = cookie_valid_params | cookie_invalid_params
    for p in cookie_params:
        if helpers.validate_parameter(p, "cookie"):
            assert p in cookie_valid_params and p not in cookie_invalid_params
        else:
            assert p in cookie_invalid_params and p not in cookie_valid_params


@pytest.mark.asyncio
async def test_rm_temp_dir_at_exit(helpers):
    from bbot.scanner import Scanner

    scan = Scanner("127.0.0.1", modules=["http"])
    await scan._prep()

    temp_dir = scan.home / "temp"

    # temp dir should exist
    assert temp_dir.exists()

    events = [e async for e in scan.async_start()]
    assert events

    # temp dir should be removed
    assert not temp_dir.exists()


# these must be top-level functions so they can be pickled for the subprocess
def _hang_forever():
    import time

    time.sleep(9999)


def _cpu_work(n):
    return sum(range(n))


@pytest.mark.asyncio
async def test_run_in_executor_mp(helpers):
    # normal tasks should complete fine
    result = await helpers.run_in_executor_mp(_cpu_work, 100_000)
    assert result == sum(range(100_000))

    # a hanging task should raise TimeoutError and auto-replace the pool
    with pytest.raises(asyncio.TimeoutError):
        await helpers.run_in_executor_mp(_hang_forever, _timeout=2)

    # pool should still work after a timeout (was replaced by _reset_process_pool)
    result = await helpers.run_in_executor_mp(_cpu_work, 50_000, _timeout=30)
    assert result == sum(range(50_000))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux-only")
def test_pool_workers_die_with_parent():
    """Pool workers must not survive when the parent is SIGKILL'd (OOM, crash, etc.)."""
    import json
    import signal
    import subprocess
    import tempfile

    script = """
import os, sys, json, time, signal, ctypes, ctypes.util, multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

_PR_SET_PDEATHSIG = 1

def _init():
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)

def _get_pid():
    time.sleep(1)
    return os.getpid()

# use fork context explicitly -- forkserver on 3.14 adds an intermediary process
# that complicates the parent-death chain; PR_SET_PDEATHSIG itself is start-method-agnostic
ctx = mp.get_context("fork")
pool = ProcessPoolExecutor(max_workers=2, initializer=_init, mp_context=ctx)
# submit concurrently so both workers are occupied (each takes 1s)
futs = [pool.submit(_get_pid) for _ in range(2)]
pids = list(set(f.result(timeout=30) for f in futs))
# keep workers busy so they stay alive
[pool.submit(time.sleep, 3600) for _ in range(2)]
print(json.dumps(pids), flush=True)
time.sleep(3600)
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(script)
        script_path = f.name

    def _is_running(pid):
        """Check /proc to distinguish running processes from zombies."""
        try:
            with open(f"/proc/{pid}/stat") as f:
                # format: "pid (comm) state ..." -- state after the last ')'
                state = f.read().split(")")[-1].strip().split()[0]
                return state not in ("Z", "X", "x")
        except (OSError, IndexError):
            return False

    try:
        proc = subprocess.Popen([sys.executable, script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = proc.stdout.readline()
        assert line, f"Worker script exited early, stderr: {proc.stderr.read().decode()}"
        worker_pids = json.loads(line)
        assert len(worker_pids) >= 2

        # simulate OOM kill
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait()

        time.sleep(2)

        alive = [pid for pid in worker_pids if _is_running(pid)]

        # clean up survivors so they don't leak into other tests
        for pid in alive:
            os.kill(pid, signal.SIGKILL)

        assert not alive, f"Pool workers {alive} survived parent SIGKILL (zombie leak)"
    finally:
        os.unlink(script_path)


def test_simhash_similarity(helpers):
    """Test SimHash helper with increasingly different HTML pages."""

    # Base HTML page
    base_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Example Page</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>Welcome to Example Corp</h1>
        <div class="content">
            <p>This is the main content of our website.</p>
            <p>We provide excellent services to our customers.</p>
            <ul>
                <li>Service A</li>
                <li>Service B</li>
                <li>Service C</li>
            </ul>
        </div>
        <footer>Copyright 2024 Example Corp</footer>
    </body>
    </html>
    """

    # Slightly different - changed one word
    slightly_different = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Example Page</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>Welcome to Example Corp</h1>
        <div class="content">
            <p>This is the main content of our website.</p>
            <p>We provide amazing services to our customers.</p>
            <ul>
                <li>Service A</li>
                <li>Service B</li>
                <li>Service C</li>
            </ul>
        </div>
        <footer>Copyright 2024 Example Corp</footer>
    </body>
    </html>
    """

    # Moderately different - changed content section
    moderately_different = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Example Page</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>Welcome to Example Corp</h1>
        <div class="content">
            <p>This page contains different information.</p>
            <p>Our products are innovative and cutting-edge.</p>
            <ul>
                <li>Product X</li>
                <li>Product Y</li>
                <li>Product Z</li>
            </ul>
        </div>
        <footer>Copyright 2024 Example Corp</footer>
    </body>
    </html>
    """

    # Very different - completely different content
    very_different = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>News Portal</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>Latest News</h1>
        <div class="articles">
            <article>
                <h2>Breaking News Today</h2>
                <p>Important events are happening around the world.</p>
            </article>
            <article>
                <h2>Sports Update</h2>
                <p>Local team wins championship game.</p>
            </article>
        </div>
        <footer>News Corp 2024</footer>
    </body>
    </html>
    """

    # Completely different - different structure and content
    completely_different = """
    <xml version="1.0">
    <data>
        <configuration>
            <setting name="timeout">300</setting>
            <setting name="retries">5</setting>
        </configuration>
        <results>
            <item id="1">Result A</item>
            <item id="2">Result B</item>
        </results>
    </data>
    """

    # Test SimHash similarity
    simhash = helpers.simhash

    # Calculate hashes
    base_hash = simhash.hash(base_html)
    slightly_hash = simhash.hash(slightly_different)
    moderately_hash = simhash.hash(moderately_different)
    very_hash = simhash.hash(very_different)
    completely_hash = simhash.hash(completely_different)

    # Calculate similarities
    identical_similarity = simhash.similarity(base_hash, base_hash)
    slight_similarity = simhash.similarity(base_hash, slightly_hash)
    moderate_similarity = simhash.similarity(base_hash, moderately_hash)
    very_similarity = simhash.similarity(base_hash, very_hash)
    complete_similarity = simhash.similarity(base_hash, completely_hash)

    print(f"Identical: {identical_similarity:.3f}")
    print(f"Slightly different: {slight_similarity:.3f}")
    print(f"Moderately different: {moderate_similarity:.3f}")
    print(f"Very different: {very_similarity:.3f}")
    print(f"Completely different: {complete_similarity:.3f}")

    # Verify expected similarity ordering
    assert identical_similarity == 1.0, "Identical content should have similarity of 1.0"
    assert slight_similarity > moderate_similarity, (
        "Slightly different should be more similar than moderately different"
    )
    assert moderate_similarity > very_similarity, "Moderately different should be more similar than very different"
    assert very_similarity > complete_similarity, "Very different should be more similar than completely different"

    # Verify reasonable similarity ranges based on actual SimHash behavior
    # With 64-bit hashes and 3-character shingles, we get good differentiation
    assert slight_similarity > 0.90, "Slightly different content should be highly similar (>0.90)"
    assert moderate_similarity > 0.70, "Moderately different content should be quite similar (>0.70)"
    assert very_similarity > 0.50, "Very different content should have medium similarity (>0.50)"
    assert complete_similarity > 0.30, "Completely different content should have low similarity (>0.30)"
    assert complete_similarity < 0.50, "Completely different content should be clearly different (<0.50)"

    # Most importantly, verify the ordering is correct
    assert identical_similarity > slight_similarity > moderate_similarity > very_similarity > complete_similarity


def test_clean_dns_record():
    from bbot.core.helpers.misc import clean_dns_record

    assert clean_dns_record("www.example.com.") == "www.example.com"
    assert clean_dns_record("www.example.com") == "www.example.com"
    # dnspython to_text() can produce quoted strings for certain record types
    assert clean_dns_record('"d1jwhzvlef5tfb.example.com"') == "d1jwhzvlef5tfb.example.com"
    assert clean_dns_record("'d1jwhzvlef5tfb.example.com'") == "d1jwhzvlef5tfb.example.com"
    # quotes + trailing dot
    assert clean_dns_record('"d1jwhzvlef5tfb.example.com."') == "d1jwhzvlef5tfb.example.com"


@pytest.mark.asyncio
async def test_asn_helper_passes_api_key(bbot_scanner, monkeypatch):
    """ASNHelper should forward the configured bbot_io_api_key to ASNDB."""
    captured = {}

    class FakeASNDB:
        def __init__(self, bbot_io_api_key=None, verify=True):
            captured["bbot_io_api_key"] = bbot_io_api_key
            captured["verify"] = verify

    import asndb

    monkeypatch.setattr(asndb, "ASNDB", FakeASNDB)

    scan = bbot_scanner("8.8.8.8", config={"bbot_io_api_key": "test-key-xyz"})
    _ = scan.helpers.asn.client
    assert captured["bbot_io_api_key"] == "test-key-xyz"

    captured.clear()
    scan2 = bbot_scanner("8.8.8.8")
    _ = scan2.helpers.asn.client
    assert captured["bbot_io_api_key"] is None


@pytest.mark.asyncio
async def test_asn_helper_circuit_breaker(bbot_scanner, monkeypatch):
    """ASNHelper should stop making requests after consecutive failures."""
    from unittest.mock import AsyncMock, MagicMock

    import asndb

    mock_client = MagicMock()
    mock_client.lookup_ip = AsyncMock(side_effect=Exception("connection refused"))
    monkeypatch.setattr(asndb, "ASNDB", lambda **kw: mock_client)

    scan = bbot_scanner("8.8.8.8")
    asn_helper = scan.helpers.asn
    assert asn_helper.FAILURE_THRESHOLD == 5

    # First FAILURE_THRESHOLD calls should each hit the network and return UNKNOWN_ASN
    for i in range(asn_helper.FAILURE_THRESHOLD):
        result = await asn_helper.ip_to_subnets(f"1.2.3.{i}")
        assert result == asn_helper.UNKNOWN_ASN
        assert not asn_helper._circuit_broken or i == asn_helper.FAILURE_THRESHOLD - 1

    # Circuit should now be broken
    assert asn_helper._circuit_broken
    assert mock_client.lookup_ip.call_count == asn_helper.FAILURE_THRESHOLD

    # Subsequent calls should return immediately without hitting the network
    for i in range(10):
        result = await asn_helper.ip_to_subnets(f"5.6.7.{i}")
        assert result == asn_helper.UNKNOWN_ASN
    assert mock_client.lookup_ip.call_count == asn_helper.FAILURE_THRESHOLD


@pytest.mark.asyncio
async def test_asn_helper_circuit_breaker_resets_on_success(bbot_scanner, monkeypatch):
    """A successful lookup should reset the consecutive failure counter."""
    from unittest.mock import AsyncMock, MagicMock

    import asndb

    call_count = 0

    async def lookup_ip_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            raise Exception("connection refused")
        return {"asn": 15169, "subnets": ["8.8.8.0/24"], "asn_name": "GOOGLE", "org": "Google", "country": "US"}

    mock_client = MagicMock()
    mock_client.lookup_ip = AsyncMock(side_effect=lookup_ip_side_effect)
    monkeypatch.setattr(asndb, "ASNDB", lambda **kw: mock_client)

    scan = bbot_scanner("8.8.8.8")
    asn_helper = scan.helpers.asn

    # 3 failures
    for i in range(3):
        await asn_helper.ip_to_subnets(f"1.2.3.{i}")
    assert asn_helper._consecutive_failures == 3
    assert not asn_helper._circuit_broken

    # 1 success should reset the counter
    result = await asn_helper.ip_to_subnets("8.8.8.8")
    assert result["asn"] == 15169
    assert asn_helper._consecutive_failures == 0
    assert not asn_helper._circuit_broken
