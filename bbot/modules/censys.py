from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class censys(subdomain_enum_apikey):
    """
    thanks to https://github.com/owasp-amass/amass/blob/master/resources/scripts/cert/censys.ads
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the Censys API",
        "created_date": "2022-08-04",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "max_pages": 5}
    options_desc = {
        "api_key": "Censys.io API Key in the format of 'key:secret'",
        "max_pages": "Maximum number of pages to fetch (100 results per page)",
    }

    base_url = "https://search.censys.io/api"

    async def setup(self):
        self.max_pages = self.config.get("max_pages", 5)
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/v1/account"
        resp = await self.api_request(url)
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

    async def query(self, query):
        results = set()
        cursor = ""
        for i in range(self.max_pages):
            url = f"{self.base_url}/v2/certificates/search"
            json_data = {
                "q": f"names: {query}",
                "per_page": 100,
            }
            if cursor:
                json_data.update({"cursor": cursor})
            resp = await self.api_request(
                url,
                method="POST",
                json=json_data,
            )

            if resp is None:
                break

            try:
                d = resp.json()
            except Exception as e:
                self.warning(f"Failed to parse JSON from {url} (response: {resp}): {e}")

            if resp.status_code < 200 or resp.status_code >= 400:
                if isinstance(d, dict):
                    error = d.get("error", "")
                    if error:
                        self.warning(error)
                self.verbose(f'Non-200 Status code: {resp.status_code} for query "{query}", page #{i + 1}')
                self.debug(f"Response: {resp.text}")
                break
            else:
                if d is None:
                    break
                elif not isinstance(d, dict):
                    break
                status = d.get("status", "").lower()
                result = d.get("result", {})
                hits = result.get("hits", [])
                if status != "ok" or not hits:
                    break

                for h in hits:
                    names = h.get("names", [])
                    for n in names:
                        results.add(n.strip(".*").lower())

                cursor = result.get("links", {}).get("next", "")
                if not cursor:
                    break

        return results
