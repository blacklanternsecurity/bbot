from bbot.modules.templates.github import github


class github_org(github):
    watched_events = ["DNS_NAME"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {"description": "Query Github's API for a organization and member repositories"}
    options = {"api_key": ""}
    options_desc = {"api_key": "Github token"}

    async def handle_event(self, event):
        domain = self.make_query(event)
        potential_org = domain.split(".")[0]
        if await self.validate_org(potential_org, domain):
            self.verbose(f"Search for any repositorys belonging to {potential_org} and its members")
            for repo_url in await self.query(potential_org):
                self.emit_event({"url": repo_url}, "CODE_REPOSITORY", source=event)
        else:
            self.warning(f"Unable to validate {potential_org} is within the scope of this assesment, skipping...")

    async def query(self, query):
        repos = []
        org_repos = await self.query_org_repos(query)
        repos.extend(org_repos)
        for member in await self.query_org_members(query):
            member_repos = await self.query_user_repos(member)
            repos.extend(member_repos)
        return repos

    async def query_org_repos(self, query):
        repos = []
        url = f"{self.base_url}/orgs/{self.helpers.quote(query)}/repos?per_page=100&page=" + "{page}"
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
                if not j:
                    break
                for item in j:
                    html_url = item.get("html_url", "")
                    repos.append(html_url)
        finally:
            agen.aclose()
        return repos

    async def query_org_members(self, query):
        members = []
        url = f"{self.base_url}/orgs/{self.helpers.quote(query)}/members?per_page=100&page=" + "{page}"
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
                if not j:
                    break
                for item in j:
                    login = item.get("login", "")
                    members.append(login)
        finally:
            agen.aclose()
        return members

    async def query_user_repos(self, query):
        repos = []
        url = f"{self.base_url}/users/{self.helpers.quote(query)}/repos?per_page=100&page=" + "{page}"
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
                if not j:
                    break
                for item in j:
                    html_url = item.get("html_url", "")
                    repos.append(html_url)
        finally:
            agen.aclose()
        return repos

    async def validate_org(self, input, domain):
        self.verbose(f"Validating the organization {input} is within our scope...")
        in_scope = False
        url = f"{self.base_url}/orgs/{input}"
        r = await self.helpers.request(url, headers=self.headers)
        if r is None:
            return in_scope
        status_code = getattr(r, "status_code", 0)
        if status_code == 403:
            self.warning("Github is rate-limiting us (HTTP status: 403)")
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
