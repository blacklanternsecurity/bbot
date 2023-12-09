from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class postman(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {"description": "Query Postman's API for related workspaces, collections, requests"}
    options = {"api_key": ""}
    options_desc = {"api_key": "Postman API key"}

    base_url = "https://www.postman.com"

    async def handle_event(self, event):
        query = self.make_query(event)
        self.verbose(f"Search for any postman workspaces, collections, requests belonging to {query}")
        for workspace_url, raw_urls in (await self.query(query)).items():
            workspace_event = self.make_event({"url": workspace_url}, "CODE_REPOSITORY", source=event)
            if workspace_event is None:
                continue
            self.emit_event(workspace_event)
            for raw_url in raw_urls:
                url_event = self.make_event(raw_url, "URL_UNVERIFIED", source=workspace_event, tags=["httpx-safe"])
                if not url_event:
                    continue
                url_event.scope_distance = workspace_event.scope_distance
                self.emit_event(url_event)

    async def query(self, query):
        interesting_urls = []
        url = f"{self.base_url}/_api/ws/proxy"
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
                "size": 10,
                "from": 0,
                "clientTraceId": "410e2617-e1e3-4bcb-afcc-374cbcc8e59f",
                "requestOrigin": "srp",
                "mergeEntities": True,
                "nonNestedRequests": True,
            },
        }
        r = await self.helpers.request(url, json)
        if r is None:
            return interesting_urls
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return interesting_urls
        for item in json["data"]:
            id = item["document"].get("id", "")
            entity_type = item["document"].get("entityType", "")
            if entity_type == "workspace":
                interesting_urls = await self.search_workspace(id)
            elif entity_type == "collection":
                interesting_urls = await self.search_collection(id)
            elif entity_type == "request":
                interesting_urls = await self.search_request(id)
        return interesting_urls

    async def search_workspace(self, id):
        interesting_urls = {}
        url = f"{self.base_url}/_api/workspace/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return interesting_urls
        interesting_urls.append(url)
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return interesting_urls
        collections = json["data"]["dependencies"].get("collections", [])
        for id in collections:
            _interesting_urls = await self.search_collection(id)
            interesting_urls = interesting_urls + _interesting_urls
        return interesting_urls

    async def search_collection(self, id):
        interesting_urls = {}
        url = f"{self.base_url}/_api/collection/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return interesting_urls
        interesting_urls.append(url)
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return interesting_urls
        folders = json["data"].get("folders_order", [])
        for id in folders:
            _interesting_urls = await self.search_folders(id)
            interesting_urls = interesting_urls + _interesting_urls
        return interesting_urls

    async def search_folders(self, id):
        interesting_urls = []
        url = f"{self.base_url}/_api/collection/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return []
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return []
        requests = json["data"].get("requests", [])
        for id in requests:
            _interesting_urls = await self.search_request(id)
            interesting_urls = interesting_urls + _interesting_urls
        return interesting_urls

    async def search_request(self, id):
        interesting_urls = []
        url = f"{self.base_url}/_api/request/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return []
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return []
        responses = json["data"].get("responses_order", [])
        for id in responses:
            _interesting_urls = await self.search_response(id)
            interesting_urls = interesting_urls + _interesting_urls
        return interesting_urls
    
    async def search_response(self, id):
        interesting_urls = []
        url = f"{self.base_url}/_api/response/{id}"
        r = await self.helpers.request(url)
        if r is None:
            return []
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return []
        responses = json["data"].get("responses_order", [])
        for id in responses:
            _interesting_urls = await self.search_response(id)
            interesting_urls = interesting_urls + _interesting_urls
        return interesting_urls
