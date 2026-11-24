from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class InternetData(BaseModule):
    """
    InternetData IP lookup API.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Query InternetData's API for an IP's geolocation, ASN and company.",
        "created_date": "2026-11-18",
        "author": "@UmanShahzad",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="InternetData API Key", sensitive=True, mandatory=True)

    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "https://api.internetdata.io"
    ping_url = f"{base_url}/8.8.8.8"

    async def setup(self):
        return await self.require_api_key()

    async def handle_event(self, event):
        try:
            url = f"{self.base_url}/{event.data}"
            result = await self.api_request(url)
            if result:
                geo_data = result.json()
                if not geo_data:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
        except Exception:
            self.verbose(f"Error retrieving results for {event.pretty_string}", trace=True)
            return

        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if "error" in geo_data:
            error_msg = geo_data.get("error", "")
            if error_msg:
                self.warning(error_msg)
        elif geo_data:
            # the location is nested; GEOLOCATION reads it at the top level
            location = geo_data.pop("location", {}) or {}
            geo_data.update(location)
            if "region" in location:
                geo_data["region_name"] = location["region"]
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
                context=f'{{module}} queried InternetData\'s API for "{event.pretty_string}" and found {{event.type}}: {description}',
            )
