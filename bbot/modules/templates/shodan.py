import traceback

from bbot.modules.templates.subdomain_enum import subdomain_enum


class shodan(subdomain_enum):
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}

    base_url = "https://api.shodan.io"
    ping_url = f"{base_url}/api-info?key={{api_key}}"

    async def setup(self):
        await super().setup()
        api_keys = set()
        for module_name in ("shodan", "shodan_dns", "shodan_port"):
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
        self.api_key = api_keys
        try:
            await self.ping()
            self.hugesuccess("API is ready")
            return True
        except Exception as e:
            self.trace(traceback.format_exc())
            return None, f"Error with API ({str(e).strip()})"
