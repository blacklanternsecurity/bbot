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

    async def query(self, query):
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
                "size": 100,
                "from": 0,
                "clientTraceId": "",
                "requestOrigin": "srp",
                "mergeEntities": "true",
                "nonNestedRequests": "true",
                "domain": "public",
            },
        }
        r = await self.helpers.request(url, method="POST", json=json, headers=self.headers)
        if r is None:
            return data
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return None
        return json.get("data", [])
