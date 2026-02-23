from bbot.modules.base import BaseModule


class ipwhois(BaseModule):
    """
    ipwho.is geolocation API (free, no API key required for basic use).
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query ipwho.is API for geolocation information.",
        "created_date": "2026-02-23",
        "author": "@carlospolop",
    }
    options = {"lang": ""}
    options_desc = {
        "lang": "Optional language for localized location names (ISO 639-1).",
    }
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "https://ipwho.is"

    async def setup(self):
        self.lang = str(self.config.get("lang", "")).strip()
        return True

    async def ping(self):
        await super().ping(f"{self.base_url}/8.8.8.8")

    def build_url(self, data):
        url = f"{self.base_url}/{data}"
        if self.lang:
            url = f"{url}?lang={self.lang}"
        return url

    async def handle_event(self, event):
        try:
            url = self.build_url(event.data)
            result = await self.helpers.request(url)
            if result:
                geo_data = result.json()
                if not geo_data:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
                return
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return

        if not isinstance(geo_data, dict):
            return
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if not geo_data.get("success", True):
            error_msg = geo_data.get("message", "")
            if error_msg:
                self.warning(error_msg)
            return

        country = geo_data.get("country", "unknown country")
        region = geo_data.get("region", "unknown region")
        city = geo_data.get("city", "unknown city")
        lat = geo_data.get("latitude", "")
        long = geo_data.get("longitude", "")
        description = f"{city}, {region}, {country} ({lat}, {long})"
        await self.emit_event(
            geo_data,
            "GEOLOCATION",
            event,
            context=f'{{module}} queried ipwho.is API for "{event.data}" and found {{event.type}}: {description}',
        )
