from bbot.modules.templates.postman import postman


class postman(postman):
    watched_events = ["ORG_STUB", "SOCIAL"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Postman's API for related workspaces, collections, requests and download them",
        "created_date": "2024-09-07",
        "author": "@domwhewell-sage",
    }

    reject_wildcards = False

    async def handle_event(self, event):
        # Handle postman profile
        if event.type == "SOCIAL":
            await self.handle_profile(event)
        elif event.type == "ORG_STUB":
            await self.handle_org_stub(event)

    async def handle_profile(self, event):
        profile_name = event.data.get("profile_name", "")
        self.verbose(f"Searching for postman workspaces, collections, requests belonging to {profile_name}")
        for item in await self.query(profile_name):
            workspace = item["document"]
            name = workspace["slug"]
            profile = workspace["publisherHandle"]
            if profile_name.lower() == profile.lower():
                self.verbose(f"Got {name}")
                workspace_url = f"{self.html_url}/{profile}/{name}"
                await self.emit_event(
                    {"url": workspace_url},
                    "CODE_REPOSITORY",
                    tags="postman",
                    parent=event,
                    context=f'{{module}} searched postman.com for workspaces belonging to "{profile_name}" and found "{name}" at {{event.type}}: {workspace_url}',
                )

    async def handle_org_stub(self, event):
        org_name = event.data
        self.verbose(f"Searching for any postman workspaces, collections, requests for {org_name}")
        for item in await self.query(org_name):
            workspace = item["document"]
            name = workspace["slug"]
            profile = workspace["publisherHandle"]
            self.verbose(f"Got {name}")
            workspace_url = f"{self.html_url}/{profile}/{name}"
            await self.emit_event(
                {"url": workspace_url},
                "CODE_REPOSITORY",
                tags="postman",
                parent=event,
                context=f'{{module}} searched postman.com for "{org_name}" and found matching workspace "{name}" at {{event.type}}: {workspace_url}',
            )

    async def process_workspaces(self, user=None, org=None):
        in_scope_workspaces = []
        owner = user or org
        if owner:
            self.verbose(f"Searching for postman workspaces, collections, requests for {owner}")
            for item in await self.query(owner):
                workspace = item["document"]
                self.hugesuccess(workspace)
                slug = workspace["slug"]
                profile = workspace["publisherHandle"]
                repo_url = f"{self.html_url}/{profile}/{slug}"
                workspace_id = await self.get_workspace_id(repo_url)
                if (org and workspace_id) or (user and owner.lower() == profile.lower()):
                    self.verbose(f"Found workspace ID {workspace_id} for {repo_url}")
                    data = await self.request_workspace(workspace_id)
                    in_scope = await self.validate_workspace(
                        data["workspace"], data["environments"], data["collections"]
                    )
                    if in_scope:
                        in_scope_workspaces.append({"url": repo_url, "repo_name": slug})
                    else:
                        self.verbose(
                            f"Failed to validate {repo_url} is in our scope as it does not contain any in-scope dns_names / emails"
                        )
        return in_scope_workspaces

    async def query(self, query):

        def api_page_iter(url, page, page_size, offset, **kwargs):
            kwargs["json"]["body"]["from"] = offset
            return url, kwargs

        data = []
        url = f"{self.base_url}/ws/proxy"
        json = {
            "service": "search",
            "method": "POST",
            "path": "/search-all",
            "body": {
                "queryIndices": [
                    "collaboration.workspace",
                ],
                "queryText": self.helpers.quote(query),
                "size": 25,
                "from": 0,
                "clientTraceId": "",
                "requestOrigin": "srp",
                "mergeEntities": "true",
                "nonNestedRequests": "true",
                "domain": "public",
            },
        }

        agen = self.api_page_iter(url, iter_key=api_page_iter, json=json, _json=False, headers=self.headers)
        async for r in agen:
            status_code = getattr(r, "status_code", 0)
            try:
                data.extend(json.get("data", []))
                self.hugesuccess(len(data))
            except Exception as e:
                self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                return None

        return data
