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
    scope_distance_modifier = 0
    suppress_dupes = False

    base_url = "http://api.ipstack.com/"

    def ping(self):
        r = self.helpers.request(f"{self.base_url}/check?access_key={self.api_key}")
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def handle_event(self, event):
        try:
            url = f"{self.base_url}/{event.data}?access_key={self.api_key}"
            result = self.helpers.request(url)
            if result:
                json = result.json()
                if json:
                    location = json.get("country_name")
                    city = json.get("city")
                    zip_code = json.get("zip")
                    region = json.get("region_name")
                    latitude = json.get("latitude")
                    longitude = json.get("longitude")
                    self.emit_event(
                        f"{location}, {city}, {zip_code}, {region}, {latitude}, {longitude}", "GEOLOCATION", event
                    )
                else:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}")
            self.trace()
