from bbot.modules.templates.subdomain_enum import subdomain_enum


class shodan(subdomain_enum):
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}

    base_url = "https://api.shodan.io"

    async def setup(self):
        await super().setup()
        self.api_key = None
        for module_name in ("shodan", "shodan_dns", "shodan_port"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if api_key:
                self.api_key = api_key
                break
        if not self.api_key:
            if self.auth_required:
                return None, "No API key set"
        try:
            await self.ping()
            self.hugesuccess(f"API is ready")
            return True
        except Exception as e:
            return None, f"Error with API ({str(e).strip()})"
        return True

    async def ping(self):
        url = f"{self.base_url}/api-info?key={self.api_key}"
        r = await self.request_with_fail_count(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content
