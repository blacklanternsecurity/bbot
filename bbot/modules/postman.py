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
    options = {"api_key": ""}
    options_desc = {"api_key": "Postman API Key"}
    reject_wildcards = False

    async def handle_event(self, event):
        # Handle postman profile
        if event.type == "SOCIAL":
            owner = event.data.get("profile_name", "")
            in_scope_workspaces = await self.process_workspaces(user=owner)
        elif event.type == "ORG_STUB":
            owner = event.data
            in_scope_workspaces = await self.process_workspaces(org=owner)
        if in_scope_workspaces:
            for workspace in in_scope_workspaces:
                repo_url = workspace["url"]
                repo_name = workspace["repo_name"]
                if event.type == "SOCIAL":
                    context = f'{{module}} searched postman.com for workspaces belonging to "{owner}" and found "{repo_name}" at {{event.type}}: {repo_url}'
                elif event.type == "ORG_STUB":
                    context = f'{{module}} searched postman.com for "{owner}" and found matching workspace "{repo_name}" at {{event.type}}: {repo_url}'
                await self.emit_event(
                    {"url": repo_url},
                    "CODE_REPOSITORY",
                    tags="postman",
                    parent=event,
                    context=context,
                )

    async def process_workspaces(self, user=None, org=None):
        in_scope_workspaces = []
        owner = user or org
        if owner:
            self.verbose(f"Searching for postman workspaces, collections, requests for {owner}")
            for item in await self.query(owner):
                workspace = item["document"]
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

        agen = self.api_page_iter(
            url, page_size=25, method="POST", iter_key=api_page_iter, json=json, _json=False, headers=self.headers
        )
        async for r in agen:
            status_code = getattr(r, "status_code", 0)
            if status_code != 200:
                self.debug(f"Reached end of postman search results (url: {r.url}) with status code {status_code}")
                break
            try:
                data.extend(r.json().get("data", []))
            except Exception as e:
                self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                return None

        return data
