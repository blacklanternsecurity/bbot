from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class github(subdomain_enum_apikey):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    base_url = "https://api.github.com"

    async def optional_api_key(self):
        self.api_key = None
        for module_name in ("github", "github_codesearch", "github_org"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if api_key:
                self.api_key = api_key
                break
        if self.api_key:
            try:
                await self.ping()
                self.hugesuccess(f"API is ready")
                self.headers = {"Authorization": f"token {self.api_key}"}
                return True
            except Exception as e:
                return None, f"Error with API ({str(e).strip()})"
        else:
            self.headers = {}
            return True

    async def setup(self):
        self.processed = set()
        return await self.optional_api_key()

    async def ping(self):
        url = f"{self.base_url}/zen"
        response = await self.helpers.request(url)
        assert getattr(response, "status_code", 0) == 200
