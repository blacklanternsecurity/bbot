from .base import ModuleTestBase


class TestIP2Location(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"ip2location": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="http://api.ip2location.io/?key=asdf&ip=8.8.8.8&format=json&source=bbot",
            json={
                "ip": "8.8.8.8",
                "country_code": "US",
                "country_name": "United States of America",
                "region_name": "California",
                "city_name": "Mountain View",
                "latitude": 37.405992,
                "longitude": -122.078515,
                "zip_code": "94043",
                "time_zone": "-07:00",
                "asn": "15169",
                "as": "Google LLC",
                "is_proxy": False,
            },
        )

    def check(self, module_test, events):
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "8.8.8.8" and e.data["city_name"] == "Mountain View"
            for e in events
        ), "Failed to geolocate IP"
