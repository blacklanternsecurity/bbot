from .shodan_dns import shodan_dns


class Ipstack(shodan_dns):
    """
    Ipstack GeoIP
    Leverages the ipstack.com API to geolocate a host by IP address.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe"]
    meta = {"description": "Query IPStack's API for GeoIP ", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "IPStack GeoIP API Key"}
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ipstack.com/"

    async def filter_event(self, event):
        return True

    async def ping(self):
        url = f"{self.base_url}/check?access_key={self.api_key}"
        r = await self.request_with_fail_count(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    async def handle_event(self, event):
        try:
            url = f"{self.base_url}/{event.data}?access_key={self.api_key}"
            result = await self.request_with_fail_count(url)
            if result:
                j = result.json()
                if not j:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return
        geo_data = {
            "ip": j.get("ip"),
            "country": j.get("country_name"),
            "city": j.get("city"),
            "zip_code": j.get("zip"),
            "region": j.get("region_name"),
            "latitude": j.get("latitude"),
            "longitude": j.get("longitude"),
        }
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if geo_data:
            event_data = ", ".join(f"{k.capitalize()}: {v}" for k, v in geo_data.items())
            self.emit_event(event_data, "GEOLOCATION", event)
        elif "error" in j:
            error_msg = j.get("error").get("info", "")
            if error_msg:
                self.warning(error_msg)
