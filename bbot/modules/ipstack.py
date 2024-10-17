from bbot.modules.base import BaseModule


class Ipstack(BaseModule):
    """
    Ipstack GeoIP
    Leverages the ipstack.com API to geolocate a host by IP address.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query IPStack's GeoIP API",
        "created_date": "2022-11-26",
        "author": "@tycoonslive",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "IPStack GeoIP API Key"}
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ipstack.com"
    ping_url = f"{base_url}/check?access_key={{api_key}}"

    async def setup(self):
        return await self.require_api_key()

    async def handle_event(self, event):
        try:
            url = f"{self.base_url}/{event.data}?access_key={{api_key}}"
            result = await self.api_request(url)
            if result:
                geo_data = result.json()
                if not geo_data:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if "error" in geo_data:
            error_msg = geo_data.get("error").get("info", "")
            if error_msg:
                self.warning(error_msg)
        elif geo_data:
            country = geo_data.get("country_name", "unknown country")
            region = geo_data.get("region_name", "unknown region")
            city = geo_data.get("city", "unknown city")
            lat = geo_data.get("latitude", "")
            long = geo_data.get("longitude", "")
            description = f"{city}, {region}, {country} ({lat}, {long})"
            await self.emit_event(
                geo_data,
                "GEOLOCATION",
                event,
                context=f'{{module}} queried ipstack.com\'s API for "{event.data}" and found {{event.type}}: {description}',
            )
