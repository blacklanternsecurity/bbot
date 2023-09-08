from .shodan_dns import shodan_dns


class IP2Locationio(shodan_dns):
    '''
        IP2Location.io Geolocation API.
    '''

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe"]
    meta = {"description": "Query IP2location.io's API for geolocation information. ", "auth_required": True}
    options = {"api_key": "", "lang": ""}
    options_desc = {"api_key": "IP2location.io API Key", "lang": "Translation information(ISO639-1). The translation is only applicable for continent, country, region and city name."}
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ip2location.io/"

    async def filter_event(self, event):
        return True

    async def handle_event(self, event):
        try:
            # url = f"{self.base_url}/?key={self.api_key}&ip={event.data}&format=json&source=bbot"
            # if self.lang != "":
            if self.config.get("lang") != "":
                url = f"{self.base_url}/?key={self.api_key}&ip={event.data}&lang={self.config.get('lang')}&format=json&source=bbot"
            else:
                url = f"{self.base_url}/?key={self.api_key}&ip={event.data}&format=json&source=bbot"
            result = await self.request_with_fail_count(url)
            if result:
                j = result.json()
                if not j:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
        # except Exception:
        except Exception as err:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            # print(f"Unexpected {err=}, {type(err)=}")
            return
        '''
        geo_data = {
            "ip": j.get("ip"),
            "country": j.get("country_name"),
            "city": j.get("city_name"),
            "zip_code": j.get("zip_code"),
            "region": j.get("region_name"),
            "latitude": j.get("latitude"),
            "longitude": j.get("longitude"),
        }'''
        geo_data = j
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if geo_data:
            # event_data = ", ".join(f"{k.capitalize()}: {v}" for k, v in geo_data.items())
            event_data = ", ".join(f"{k}: {v}" for k, v in geo_data.items())
            self.emit_event(event_data, "GEOLOCATION", event)
        elif "error" in j:
            error_msg = j.get("error").get("error_message", "")
            if error_msg:
                self.warning(error_msg)