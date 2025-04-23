from .base import ModuleTestBase


class TestIPStack(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"ipstack": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="http://api.ipstack.com/check?access_key=asdf",
            json={
                "ip": "1.2.3.4",
                "type": "ipv4",
                "continent_code": "NA",
                "continent_name": "North America",
                "country_code": "US",
                "country_name": "United States",
                "region_code": "FL",
                "region_name": "Florida",
                "city": "Cape Canaveral",
                "zip": "12345",
                "latitude": 47.89263153076172,
                "longitude": -97.04190063476562,
                "location": {
                    "geoname_id": 5059429,
                    "capital": "Washington D.C.",
                    "languages": [{"code": "en", "name": "English", "native": "English"}],
                    "country_flag": "https://assets.ipstack.com/flags/us.svg",
                    "country_flag_emoji": "🇺🇸",
                    "country_flag_emoji_unicode": "U+1F1FA U+1F1F8",
                    "calling_code": "1",
                    "is_eu": False,
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="http://api.ipstack.com/8.8.8.8?access_key=asdf",
            json={
                "ip": "8.8.8.8",
                "type": "ipv4",
                "continent_code": "NA",
                "continent_name": "North America",
                "country_code": "US",
                "country_name": "United States",
                "region_code": "OH",
                "region_name": "Ohio",
                "city": "Glenmont",
                "zip": "44628",
                "latitude": 40.5369987487793,
                "longitude": -82.12859344482422,
                "location": {
                    "geoname_id": None,
                    "capital": "Washington D.C.",
                    "languages": [{"code": "en", "name": "English", "native": "English"}],
                    "country_flag": "https://assets.ipstack.com/flags/us.svg",
                    "country_flag_emoji": "🇺🇸",
                    "country_flag_emoji_unicode": "U+1F1FA U+1F1F8",
                    "calling_code": "1",
                    "is_eu": False,
                },
            },
        )

    def check(self, module_test, events):
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "8.8.8.8" and e.data["city"] == "Glenmont" for e in events
        ), "Failed to geolocate IP"
