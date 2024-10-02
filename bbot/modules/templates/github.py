import traceback

from bbot.modules.base import BaseModule


class github(BaseModule):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    _qsize = 1
    base_url = "https://api.github.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = f"token {self.api_key}"
        return url, kwargs

    async def setup(self):
        await super().setup()
        self.headers = {}
        api_keys = set()
        for module_name in ("github", "github_codesearch", "github_org", "git_clone"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            for key in api_key:
                key = key.strip()
                if key:
                    api_keys.update(key)
        if not api_keys:
            if self.auth_required:
                return None, "No API key set"
        self.api_key = api_keys
        try:
            await self.ping()
            self.hugesuccess(f"API is ready")
            return True
        except Exception as e:
            self.trace(traceback.format_exc())
            return None, f"Error with API ({str(e).strip()})"
        return True

    async def ping(self):
        url = f"{self.base_url}/zen"
        response = await self.helpers.request(url, headers=self.headers)
        assert getattr(response, "status_code", 0) == 200, response.text
