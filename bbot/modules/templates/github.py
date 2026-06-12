import traceback

from bbot.modules.base import BaseModule


class github(BaseModule):
    """
    A template module for use of the GitHub API
    Inherited by several other github modules.
    """

    _qsize = 1
    base_url = "https://api.github.com"
    ping_url = f"{base_url}/zen"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = f"token {self.api_key}"
        return url, kwargs

    async def setup(self):
        await super().setup()
        self.headers = {}
        api_keys = set()
        modules_config = self.scan.config.get("modules", {})
        git_modules = [m for m in modules_config if str(m).startswith("git")]
        for module_name in git_modules:
            module_config = modules_config.get(module_name, {})
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
        return True

    async def github_graphql_request(self, graphql_query, resp_key):
        url = f"{self.base_url}/graphql"
        next_key = ""
        has_next_page = True

        while has_next_page:
            query = graphql_query.replace("{NEXT_KEY}", next_key)
            r = await self.api_request(url, method="POST", json={"query": query})
            if r is None:
                break
            status_code = getattr(r, "status_code", 0)
            if status_code == 403:
                self.warning("Github is rate-limiting us (HTTP status: 403)")
                break
            try:
                json = r.json()
            except Exception as e:
                self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                break

            data = json.get("data", {}).get(resp_key, {})
            yield data

            # Update pagination variables
            page_info = data.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            next_key = page_info.get("endCursor", "")
