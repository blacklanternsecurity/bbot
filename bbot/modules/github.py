from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class github(subdomain_enum_apikey):
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
        await self.search_code(event)
        await self.search_org(event)

    async def search_code(self, event):
        query = self.make_query(event)
        self.verbose(f"Search for any code belonging to {query}")
        for repo_url, raw_urls in (await self.query_code(query)).items():
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

    async def search_org(self, event):
        domain = self.make_query(event)
        potential_org = domain.split(".")[0]
        if await self.validate_org(potential_org, domain):
            self.verbose(f"Search for any repositorys belonging to {potential_org}")
            for repo_url, raw_urls in (await self.query_org_repos(potential_org)).items():
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
        else:
            self.warning(f"Unable to validate {potential_org} is within the scope of this assesment, skipping...")

    async def query_code(self, query):
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

    async def query_org_repos(self, query):
        repos = {}
        url = f"{self.base_url}/orgs/{self.helpers.quote(query)}/repos?per_page=100&page=" + "{page}"
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
                if not j:
                    break
                for item in j:
                    html_url = item.get("html_url", "")
                    self.verbose(f"Discovered {html_url}")
                    repo_name = item.get("full_name", "")
                    repo_contents = await self.query_repo_contents(repo_name)
                    repos[html_url] = repo_contents
        finally:
            agen.aclose()
        return repos

    async def query_repo_contents(self, query, path=None):
        contents = []
        if path:
            url = f"{self.base_url}/repos/{self.helpers.quote(query)}/contents/{path}"
        else:
            url = f"{self.base_url}/repos/{self.helpers.quote(query)}/contents"
        r = await self.helpers.request(url, headers=self.headers)
        if r is None:
            return contents
        status_code = getattr(r, "status_code", 0)
        if status_code == 429:
            "Github is rate-limiting us (HTTP status: 429)"
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return contents
        for item in json:
            raw_url = item.get("download_url", "")
            if not raw_url:
                path = item.get("path", "")
                sub_dir_files = await self.query_repo_contents(query, path=path)
                contents = contents + sub_dir_files
            else:
                self.verbose(f"Got {raw_url} from {query}")
                contents.append(raw_url)
        return contents

    async def validate_org(self, input, domain):
        self.verbose(f"Validating the organization {input} is within our scope...")
        in_scope = False
        url = f"{self.base_url}/orgs/{input}"
        r = await self.helpers.request(url)
        if r is None:
            return in_scope
        status_code = getattr(r, "status_code", 0)
        if status_code == 429:
            "Github is rate-limiting us (HTTP status: 429)"
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return in_scope
        blog = json.get("blog", "")
        if domain in blog:
            self.verbose(f"{input} is within the scope of this assesment")
            in_scope = True
        return in_scope

    @staticmethod
    def raw_url(url):
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
