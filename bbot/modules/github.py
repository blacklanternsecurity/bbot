from bbot.modules.shodan_dns import shodan_dns


class github(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {"description": "Query Github's API for related repositories", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "Github token"}

    base_url = "https://api.github.com"

    async def setup(self):
        ret = await super().setup()
        self.headers = {"Authorization": f"token {self.api_key}"}
        return ret

    async def ping(self):
        url = f"{self.base_url}/zen"
        response = await self.helpers.request(url)
        assert getattr(response, "status_code", 0) == 200

    async def handle_event(self, event):
        query = self.make_query(event)
        for repo_url, raw_urls in (await self.query(query)).items():
            repo_event = self.make_event({"url": repo_url}, "CODE_REPOSITORY", source=event)
            if repo_event is None:
                continue
            self.emit_event(repo_event)
            for raw_url in raw_urls:
                url_event = self.make_event(raw_url, "URL_UNVERIFIED", source=repo_event, tags=["httpx-safe"])
                if not url_event:
                    continue
                url_event.scope_distance = repo_event.scope_distance
                self.emit_event(url_event)

    async def query(self, query):
        repos = {}
        url = f"{self.base_url}/search/code?per_page=100&type=Code&q={self.helpers.quote(query)}&page=" + "{page}"
        agen = self.helpers.api_page_iter(url, headers=self.headers, json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 429:
                    "Github is rate-limiting us (HTTP status: 429)"
                    break
                try:
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                items = j.get("items", [])
                if not items:
                    break
                for item in items:
                    htlm_url = item.get("html_url", "")
                    raw_url = self.raw_url(htlm_url)
                    repo_url = item.get("repository", {}).get("html_url", "")
                    if raw_url and repo_url:
                        try:
                            repos[repo_url].append(raw_url)
                        except KeyError:
                            repos[repo_url] = [raw_url]
        finally:
            agen.aclose()
        return repos

    @staticmethod
    def raw_url(url):
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
