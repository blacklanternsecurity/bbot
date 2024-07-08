from .base import ModuleTestBase


class TestASNBGPView(ModuleTestBase):
    targets = ["8.8.8.8"]
    module_name = "asn"
    config_overrides = {"scope": {"report_distance": 2}}

    response_get_asn_bgpview = {
        "status": "ok",
        "status_message": "Query was successful",
        "data": {
            "ip": "8.8.8.8",
            "ptr_record": "dns.google",
            "prefixes": [
                {
                    "prefix": "8.8.8.0/24",
                    "ip": "8.8.8.0",
                    "cidr": 24,
                    "asn": {"asn": 15169, "name": "GOOGLE", "description": "Google LLC", "country_code": "US"},
                    "name": "LVLT-GOGL-8-8-8",
                    "description": "Google LLC",
                    "country_code": "US",
                }
            ],
            "rir_allocation": {
                "rir_name": "ARIN",
                "country_code": None,
                "ip": "8.0.0.0",
                "cidr": 9,
                "prefix": "8.0.0.0/9",
                "date_allocated": "1992-12-01 00:00:00",
                "allocation_status": "allocated",
            },
            "iana_assignment": {
                "assignment_status": "legacy",
                "description": "Administered by ARIN",
                "whois_server": "whois.arin.net",
                "date_assigned": None,
            },
            "maxmind": {"country_code": None, "city": None},
        },
        "@meta": {"time_zone": "UTC", "api_version": 1, "execution_time": "567.18 ms"},
    }
    response_get_emails_bgpview = {
        "status": "ok",
        "status_message": "Query was successful",
        "data": {
            "asn": 15169,
            "name": "GOOGLE",
            "description_short": "Google LLC",
            "description_full": ["Google LLC"],
            "country_code": "US",
            "website": "https://about.google/intl/en/",
            "email_contacts": ["network-abuse@google.com", "arin-contact@google.com"],
            "abuse_contacts": ["network-abuse@google.com"],
            "looking_glass": None,
            "traffic_estimation": None,
            "traffic_ratio": "Mostly Outbound",
            "owner_address": ["1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "US"],
            "rir_allocation": {
                "rir_name": "ARIN",
                "country_code": "US",
                "date_allocated": "2000-03-30 00:00:00",
                "allocation_status": "assigned",
            },
            "iana_assignment": {
                "assignment_status": None,
                "description": None,
                "whois_server": None,
                "date_assigned": None,
            },
            "date_updated": "2023-02-07 06:39:11",
        },
        "@meta": {"time_zone": "UTC", "api_version": 1, "execution_time": "56.55 ms"},
    }

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.bgpview.io/ip/8.8.8.8", json=self.response_get_asn_bgpview
        )
        module_test.httpx_mock.add_response(
            url="https://api.bgpview.io/asn/15169", json=self.response_get_emails_bgpview
        )
        module_test.module.sources = ["bgpview"]

    def check(self, module_test, events):
        assert any(e.type == "ASN" for e in events)
        assert any(e.type == "EMAIL_ADDRESS" for e in events)


class TestASNRipe(ModuleTestBase):
    targets = ["8.8.8.8"]
    module_name = "asn"
    config_overrides = {"scope": {"report_distance": 2}}

    response_get_asn_ripe = {
        "messages": [],
        "see_also": [],
        "version": "1.1",
        "data_call_name": "network-info",
        "data_call_status": "supported",
        "cached": False,
        "data": {"asns": ["15169"], "prefix": "8.8.8.0/24"},
        "query_id": "20230217212133-f278ff23-d940-4634-8115-a64dee06997b",
        "process_time": 5,
        "server_id": "app139",
        "build_version": "live.2023.2.1.142",
        "status": "ok",
        "status_code": 200,
        "time": "2023-02-17T21:21:33.428469",
    }
    response_get_asn_metadata_ripe = {
        "messages": [],
        "see_also": [],
        "version": "4.1",
        "data_call_name": "whois",
        "data_call_status": "supported - connecting to ursa",
        "cached": False,
        "data": {
            "records": [
                [
                    {"key": "ASNumber", "value": "15169", "details_link": None},
                    {"key": "ASName", "value": "GOOGLE", "details_link": None},
                    {"key": "ASHandle", "value": "15169", "details_link": "https://stat.ripe.net/AS15169"},
                    {"key": "RegDate", "value": "2000-03-30", "details_link": None},
                    {
                        "key": "Ref",
                        "value": "https://rdap.arin.net/registry/autnum/15169",
                        "details_link": "https://rdap.arin.net/registry/autnum/15169",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgAbuseHandle", "value": "ABUSE5250-ARIN", "details_link": None},
                    {"key": "OrgAbuseName", "value": "Abuse", "details_link": None},
                    {"key": "OrgAbusePhone", "value": "+1-650-253-0000", "details_link": None},
                    {
                        "key": "OrgAbuseEmail",
                        "value": "network-abuse@google.com",
                        "details_link": "mailto:network-abuse@google.com",
                    },
                    {
                        "key": "OrgAbuseRef",
                        "value": "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                        "details_link": "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgName", "value": "Google LLC", "details_link": None},
                    {"key": "OrgId", "value": "GOGL", "details_link": None},
                    {"key": "Address", "value": "1600 Amphitheatre Parkway", "details_link": None},
                    {"key": "City", "value": "Mountain View", "details_link": None},
                    {"key": "StateProv", "value": "CA", "details_link": None},
                    {"key": "PostalCode", "value": "94043", "details_link": None},
                    {"key": "Country", "value": "US", "details_link": None},
                    {"key": "RegDate", "value": "2000-03-30", "details_link": None},
                    {
                        "key": "Comment",
                        "value": "Please note that the recommended way to file abuse complaints are located in the following links.",
                        "details_link": None,
                    },
                    {
                        "key": "Comment",
                        "value": "To report abuse and illegal activity: https://www.google.com/contact/",
                        "details_link": None,
                    },
                    {
                        "key": "Comment",
                        "value": "For legal requests: http://support.google.com/legal",
                        "details_link": None,
                    },
                    {"key": "Comment", "value": "Regards,", "details_link": None},
                    {"key": "Comment", "value": "The Google Team", "details_link": None},
                    {
                        "key": "Ref",
                        "value": "https://rdap.arin.net/registry/entity/GOGL",
                        "details_link": "https://rdap.arin.net/registry/entity/GOGL",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "OrgTechHandle", "value": "ZG39-ARIN", "details_link": None},
                    {"key": "OrgTechName", "value": "Google LLC", "details_link": None},
                    {"key": "OrgTechPhone", "value": "+1-650-253-0000", "details_link": None},
                    {
                        "key": "OrgTechEmail",
                        "value": "arin-contact@google.com",
                        "details_link": "mailto:arin-contact@google.com",
                    },
                    {
                        "key": "OrgTechRef",
                        "value": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                        "details_link": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
                [
                    {"key": "RTechHandle", "value": "ZG39-ARIN", "details_link": None},
                    {"key": "RTechName", "value": "Google LLC", "details_link": None},
                    {"key": "RTechPhone", "value": "+1-650-253-0000", "details_link": None},
                    {"key": "RTechEmail", "value": "arin-contact@google.com", "details_link": None},
                    {
                        "key": "RTechRef",
                        "value": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                        "details_link": None,
                    },
                    {"key": "source", "value": "ARIN", "details_link": None},
                ],
            ],
            "irr_records": [],
            "authorities": ["arin"],
            "resource": "15169",
            "query_time": "2023-02-17T21:25:00",
        },
        "query_id": "20230217212529-75f57efd-59f4-473f-8bdd-803062e94290",
        "process_time": 268,
        "server_id": "app143",
        "build_version": "live.2023.2.1.142",
        "status": "ok",
        "status_code": 200,
        "time": "2023-02-17T21:25:29.417812",
    }

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
            json=self.response_get_asn_ripe,
        )
        module_test.httpx_mock.add_response(
            url="https://stat.ripe.net/data/whois/data.json?resource=15169",
            json=self.response_get_asn_metadata_ripe,
        )
        module_test.module.sources = ["ripe"]

    def check(self, module_test, events):
        assert any(e.type == "ASN" for e in events)
        assert any(e.type == "EMAIL_ADDRESS" for e in events)
