from bbot.modules.base import BaseModule


class IP2Location(BaseModule):
    """
    IP2Location.io Geolocation API.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe"]
    meta = {"description": "Query IP2location.io's API for geolocation information. ", "auth_required": True}
    options = {"api_key": "", "lang": ""}
    options_desc = {
        "api_key": "IP2location.io API Key",
        "lang": "Translation information(ISO639-1). The translation is only applicable for continent, country, region and city name.",
    }
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ip2location.io"

    async def setup(self):
        await self.require_api_key()
        self.lang = self.config.get("lang", "")
        return True

    async def ping(self):
        url = self.build_url("8.8.8.8")
        r = await self.request_with_fail_count(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def build_url(self, data):
        url = f"{self.base_url}/?key={self.api_key}&ip={data}&format=json&source=bbot"
        if self.lang:
            url = f"{url}&lang={self.lang}"
        return url

    async def handle_event(self, event):
        try:
            url = self.build_url(event.data)
            result = await self.request_with_fail_count(url)
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
        if geo_data:
            self.emit_event(geo_data, "GEOLOCATION", event)
        elif "error" in geo_data:
            error_msg = geo_data.get("error").get("error_message", "")
            if error_msg:
                self.warning(error_msg)
