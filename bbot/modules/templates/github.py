from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class github(subdomain_enum_apikey):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe"]
    options = {"api_key": ""}
    options_desc = {"api_key": "Github token"}

    base_url = "https://api.github.com"
    headers = {}

    async def setup(self):
        ret = await super().setup()
        self.headers = {"Authorization": f"token {self.api_key}"}
        return ret

    async def ping(self):
        url = f"{self.base_url}/zen"
        response = await self.helpers.request(url)
        assert getattr(response, "status_code", 0) == 200
