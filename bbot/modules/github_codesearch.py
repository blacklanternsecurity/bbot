from bbot.modules.templates.github import github


class github_codesearch(github):
    meta = {"description": "Query Github's API for code containing the target domain name", "auth_required": True}

    async def handle_event(self, event):
        query = self.make_query(event)
        for repo_url in (await self.query(query)).items():
            self.emit_event({"url": repo_url}, "CODE_REPOSITORY", source=event)

    async def query(self, query):
        repos = []
        url = f"{self.base_url}/search/code?per_page=100&type=Code&q={self.helpers.quote(query)}&page=" + "{page}"
        agen = self.helpers.api_page_iter(url, headers=self.headers, json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 403:
                    self.warning("Github is rate-limiting us (HTTP status: 403)")
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
                    repos.append(html_url)
        finally:
            agen.aclose()
        return repos
