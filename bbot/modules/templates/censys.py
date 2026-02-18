import traceback

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class censys(subdomain_enum_apikey):
    """
    Base template for Censys API modules.
    Provides common authentication and API request handling.
    """

    options = {"api_key": ""}
    options_desc = {"api_key": "Censys.io API Key in the format of 'key:secret'"}

    base_url = "https://search.censys.io/api"

    async def setup(self):
        await super().setup()
        api_keys = set()
        for module_name in ("censys", "censys_dns", "censys_ip"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            for key in api_key:
                key = key.strip()
                if key:
                    api_keys.add(key)
        if not api_keys:
            if self.auth_required:
                return None, "No API key set"
        self.api_key = api_keys.pop() if api_keys else ""
        try:
            await self.ping()
            self.hugesuccess("API is ready")
            return True
        except Exception as e:
            self.trace(traceback.format_exc())
            return None, f"Error with API ({str(e).strip()})"

    async def ping(self):
        url = f"{self.base_url}/v1/account"
        resp = await self.api_request(url, retry_on_http_429=False)
        d = resp.json()
        assert isinstance(d, dict), f"Invalid response from {url}: {resp}"
        quota = d.get("quota", {})
        used = int(quota.get("used", 0))
        allowance = int(quota.get("allowance", 0))
        assert used < allowance, "No quota remaining"

    def prepare_api_request(self, url, kwargs):
        api_id, api_secret = self.api_key.split(":", 1)
        kwargs["auth"] = (api_id, api_secret)
        return url, kwargs
