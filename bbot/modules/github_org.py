from bbot.modules.templates.github import github


class github_org(github):
    watched_events = ["ORG_STUB", "SOCIAL"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Github's API for organization and member repositories",
        "created_date": "2023-12-14",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "include_members": True, "include_member_repos": False}
    options_desc = {
        "api_key": "Github token",
        "include_members": "Enumerate organization members",
        "include_member_repos": "Also enumerate organization members' repositories",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.include_members = self.config.get("include_members", True)
        self.include_member_repos = self.config.get("include_member_repos", False)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "SOCIAL":
            if event.data.get("platform", "") != "github":
                return False, "event is not a github profile"
            # reject org members if the setting isn't enabled
            # this prevents gathering of org member repos
            if (not self.include_member_repos) and ("github-org-member" in event.tags):
                return False, "include_member_repos is False"
        return True

    async def handle_event(self, event):
        # handle github profile
        if event.type == "SOCIAL":
            user = event.data.get("profile_name", "")
            in_scope = False
            if "github-org-member" in event.tags:
                is_org = False
            elif "github-org" in event.tags:
                is_org = True
                in_scope = True
            else:
                is_org, in_scope = await self.validate_org(user)

            # find repos from user/org (SOCIAL --> CODE_REPOSITORY)
            repos = []
            if is_org:
                if in_scope:
                    self.verbose(f"Searching for repos belonging to organization {user}")
                    repos = await self.query_org_repos(user)
                else:
                    self.verbose(f"Organization {user} does not appear to be in-scope")
            elif "github-org-member" in event.tags:
                self.verbose(f"Searching for repos belonging to user {user}")
                repos = await self.query_user_repos(user)
            for repo_url in repos:
                repo_event = self.make_event({"url": repo_url}, "CODE_REPOSITORY", tags="git", parent=event)
                if not repo_event:
                    continue
                await self.emit_event(
                    repo_event,
                    context=f"{{module}} listed repos for GitHub profile and discovered {{event.type}}: {repo_url}",
                )

            # find members from org (SOCIAL --> SOCIAL)
            if is_org and self.include_members:
                self.verbose(f"Searching for any members belonging to {user}")
                org_members = await self.query_org_members(user)
                for member in org_members:
                    member_url = f"https://github.com/{member}"
                    event_data = {"platform": "github", "profile_name": member, "url": member_url}
                    member_event = self.make_event(event_data, "SOCIAL", tags="github-org-member", parent=event)
                    if member_event:
                        await self.emit_event(
                            member_event,
                            context=f"{{module}} listed members of GitHub organization and discovered {{event.type}}: {member_url}",
                        )

        # find valid orgs from stub (ORG_STUB --> SOCIAL)
        elif event.type == "ORG_STUB":
            user = event.data
            self.verbose(f"Validating whether the organization {user} is within our scope...")
            is_org, in_scope = await self.validate_org(user)
            if "target" in event.tags:
                in_scope = True
            if not is_org or not in_scope:
                self.verbose(f"Unable to validate that {user} is in-scope, skipping...")
                return

            user_url = f"https://github.com/{user}"
            event_data = {"platform": "github", "profile_name": user, "url": user_url}
            github_org_event = self.make_event(event_data, "SOCIAL", tags="github-org", parent=event)
            if github_org_event:
                await self.emit_event(
                    github_org_event,
                    context=f'{{module}} tried "{user}" as GitHub profile and discovered {{event.type}}: {user_url}',
                )

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
                if status_code != 200:
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
                if status_code != 200:
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
                if status_code != 200:
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

    async def validate_org(self, org):
        is_org = False
        in_scope = False
        url = f"{self.base_url}/orgs/{org}"
        r = await self.helpers.request(url, headers=self.headers)
        if r is None:
            return is_org, in_scope
        status_code = getattr(r, "status_code", 0)
        if status_code == 403:
            self.warning("Github is rate-limiting us (HTTP status: 403)")
            return is_org, in_scope
        if status_code == 200:
            is_org = True
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return is_org, in_scope
        for k, v in json.items():
            if (
                isinstance(v, str)
                and (
                    self.helpers.is_dns_name(v, include_local=False)
                    or self.helpers.is_url(v)
                    or self.helpers.is_email(v)
                )
                and self.scan.in_scope(v)
            ):
                self.verbose(f'Found in-scope key "{k}": "{v}" for {org}, it appears to be in-scope')
                in_scope = True
                break
        return is_org, in_scope
