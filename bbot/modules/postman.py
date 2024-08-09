from bbot.modules.templates.subdomain_enum import subdomain_enum


class postman(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Postman's API for related workspaces, collections, requests",
        "created_date": "2023-12-23",
        "author": "@domwhewell-sage",
    }

    base_url = "https://www.postman.com/_api"

    headers = {
        "Content-Type": "application/json",
        "X-App-Version": "10.18.8-230926-0808",
        "X-Entity-Team-Id": "0",
        "Origin": "https://www.postman.com",
        "Referer": "https://www.postman.com/search?q=&scope=public&type=all",
    }

    reject_wildcards = False

    async def handle_event(self, event):
        query = self.make_query(event)
        self.verbose(f"Searching for any postman workspaces, collections, requests belonging to {query}")
        for url, context in await self.query(query):
            await self.emit_event(url, "URL_UNVERIFIED", parent=event, tags="httpx-safe", context=context)

    async def query(self, query):
        interesting_urls = []
        url = f"{self.base_url}/ws/proxy"
        json = {
            "service": "search",
            "method": "POST",
            "path": "/search-all",
            "body": {
                "queryIndices": [
                    "collaboration.workspace",
                    "runtime.collection",
                    "runtime.request",
                    "adp.api",
                    "flow.flow",
                    "apinetwork.team",
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
            return interesting_urls
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return interesting_urls
        workspaces = []
        for item in json.get("data", {}):
            for workspace in item.get("document", {}).get("workspaces", []):
                if workspace not in workspaces:
                    workspaces.append(workspace)
        for item in workspaces:
            id = item.get("id", "")
            name = item.get("name", "")
            tldextract = self.helpers.tldextract(query)
            if tldextract.domain.lower() in name.lower():
                self.verbose(f"Discovered workspace {name} ({id})")
                workspace_url = f"{self.base_url}/workspace/{id}"
                interesting_urls.append(
                    (
                        workspace_url,
                        f'{{module}} searched postman.com for "{query}" and found matching workspace "{name}" at {{event.type}}: {workspace_url}',
                    )
                )
                environments, collections = await self.search_workspace(id)
                globals_url = f"{self.base_url}/workspace/{id}/globals"
                interesting_urls.append(
                    (
                        globals_url,
                        f'{{module}} searched postman.com for "{query}", found matching workspace "{name}" at {workspace_url}, and found globals at {{event.type}}: {globals_url}',
                    )
                )
                for e_id in environments:
                    env_url = f"{self.base_url}/environment/{e_id}"
                    interesting_urls.append(
                        (
                            env_url,
                            f'{{module}} searched postman.com for "{query}", found matching workspace "{name}" at {workspace_url}, enumerated environments, and found {{event.type}}: {env_url}',
                        )
                    )
                for c_id in collections:
                    collection_url = f"{self.base_url}/collection/{c_id}"
                    interesting_urls.append(
                        (
                            collection_url,
                            f'{{module}} searched postman.com for "{query}", found matching workspace "{name}" at {workspace_url}, enumerated collections, and found {{event.type}}: {collection_url}',
                        )
                    )
                requests = await self.search_collections(id)
                for r_id in requests:
                    request_url = f"{self.base_url}/request/{r_id}"
                    interesting_urls.append(
                        (
                            request_url,
                            f'{{module}} searched postman.com for "{query}", found matching workspace "{name}" at {workspace_url}, enumerated requests, and found {{event.type}}: {request_url}',
                        )
                    )
            else:
                self.verbose(f"Skipping workspace {name} ({id}) as it does not appear to be in scope")
        return interesting_urls

    async def search_workspace(self, id):
        url = f"{self.base_url}/workspace/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return [], []
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
            if not isinstance(json, dict):
                raise ValueError(f"Got unexpected value for JSON: {json}")
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return [], []
        environments = json.get("data", {}).get("dependencies", {}).get("environments", [])
        collections = json.get("data", {}).get("dependencies", {}).get("collections", [])
        return environments, collections

    async def search_collections(self, id):
        request_ids = []
        url = f"{self.base_url}/list/collection?workspace={id}"
        r = await self.helpers.request(url, method="POST")
        if r is None:
            return request_ids
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return request_ids
        for item in json.get("data", {}):
            request_ids.extend(await self.parse_collection(item))
        return request_ids

    async def parse_collection(self, json):
        request_ids = []
        folders = json.get("folders", [])
        requests = json.get("requests", [])
        for folder in folders:
            request_ids.extend(await self.parse_collection(folder))
        for request in requests:
            r_id = request.get("id", "")
            request_ids.append(r_id)
        return request_ids
