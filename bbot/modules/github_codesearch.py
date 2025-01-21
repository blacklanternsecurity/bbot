from bbot.modules.templates.github import github
from bbot.modules.templates.subdomain_enum import subdomain_enum


class github_codesearch(github, subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["CODE_REPOSITORY", "URL_UNVERIFIED"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Github's API for code containing the target domain name",
        "created_date": "2023-12-14",
        "author": "@domwhewell-sage",
        "auth_required": True,
    }
    options = {"api_key": "", "limit": 100}
    options_desc = {"api_key": "Github token", "limit": "Limit code search to this many results"}

    github_raw_url = "https://raw.githubusercontent.com/"

    async def setup(self):
        self.limit = self.config.get("limit", 100)
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        for repo_url, raw_urls in (await self.query(query)).items():
            repo_event = self.make_event({"url": repo_url}, "CODE_REPOSITORY", tags="git", parent=event)
            if repo_event is None:
                continue
            await self.emit_event(
                repo_event,
                context=f'{{module}} searched github.com for "{query}" and found {{event.type}} with matching content at {repo_url}',
            )
            for raw_url in raw_urls:
                url_event = self.make_event(raw_url, "URL_UNVERIFIED", parent=repo_event, tags=["httpx-safe"])
                if not url_event:
                    continue
                await self.emit_event(
                    url_event, context=f'file matching query "{query}" is at {{event.type}}: {raw_url}'
                )

    async def query(self, query):
        repos = {}
        url = f"{self.base_url}/search/code?per_page=100&type=Code&q={self.helpers.quote(query)}&page=" + "{page}"
        agen = self.api_page_iter(url, headers=self.headers, _json=False)
        num_results = 0
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 429:
                    self.info("Github is rate-limiting us (HTTP status: 429)")
                    break
                if status_code != 200:
                    self.info(f"Unexpected response (HTTP status: {status_code})")
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
                    html_url = item.get("html_url", "")
                    raw_url = self.raw_url(html_url)
                    repo_url = item.get("repository", {}).get("html_url", "")
                    if raw_url and repo_url:
                        try:
                            repos[repo_url].append(raw_url)
                        except KeyError:
                            repos[repo_url] = [raw_url]
                        num_results += 1
                        if num_results >= self.limit:
                            break
                if num_results >= self.limit:
                    break
        finally:
            await agen.aclose()
        return repos

    def raw_url(self, url):
        return url.replace("https://github.com/", self.github_raw_url).replace("/blob/", "/")
