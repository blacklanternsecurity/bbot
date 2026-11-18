from .base import ModuleTestBase


class TestInternetData(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"internetdata": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.internetdata.io/8.8.8.8",
            json={
                "ip": "8.8.8.8",
                "is_anycast": True,
                "location": {
                    "continent": "NA",
                    "country": "US",
                    "country_name": "United States",
                    "timezone": "America/Los_Angeles",
                },
                "asn": {
                    "asn": 15169,
                    "name": "Google LLC",
                    "domain": "google.com",
                    "type": "hosting",
                    "prefix": "8.8.8.0/24",
                },
                "company": {"name": "Google LLC", "domain": "google.com"},
                "hostname": "dns.google",
            },
        )

    def check(self, module_test, events):
        assert any(
            e.type == "GEOLOCATION"
            and e.data["ip"] == "8.8.8.8"
            and e.data["country_name"] == "United States"
            and e.data["asn"]["asn"] == 15169
            for e in events
        ), "Failed to geolocate IP"
