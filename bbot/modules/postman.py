from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey

class postman(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive", "subdomain-enum", "safe"]
    meta = {"description": "Query Postman's API for related workspaces, collections, requests"}
    options = {"api_key": ""}
    options_desc = {"api_key": "Postman API key"}

    base_url = "https://www.postman.com/_api"

    headers = {
        "Content-Type": "application/json",
        "X-App-Version": "10.18.8-230926-0808",
        "X-Entity-Team-Id": "0",
        "Origin": "https://www.postman.com",
        "Referer": "https://www.postman.com/search?q=&scope=public&type=all",
    }

    async def handle_event(self, event):
        query = self.make_query(event)
        self.verbose(f"Search for any postman workspaces, collections, requests belonging to {query}")
        for url in (await self.query(query)):
            self.emit_event(url, "URL_UNVERIFIED", source=event)

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
        r = await self.helpers.request(url, json, headers=self.headers)
        if r is None:
            return interesting_urls
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return interesting_urls
        workspaces = []
        for item in json["data"]:
            for workspace in item.get("document", {}).get("workspaces", []):
                if workspace not in workspaces:
                    workspaces.append(workspace)
        for workspace in workspaces:
            id = item.get("id", "")
            interesting_urls.append(f"{self.base_url}/workspace/{id}")
            interesting_urls.append(f"{self.base_url}/workspace/{id}/globals")
            for c_id in workspace['dependencies']['collections']:
                interesting_urls.append(f'https://www.postman.com/_api/collection/{c_id}')
            requests = await self.search_collections(r_id)
            for r_id in requests:
                interesting_urls.append(f"{self.base_url}/request/{r_id}")
        return interesting_urls

    async def search_collections(self, id):
        request_ids = []
        url = f"{self.base_url}/list/collection?workspace={id}"
        r = await self.helpers.request(url)
        if r is None:
            return request_ids
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return request_ids
        for collection in json["data"]:
            request_ids.append(collection["requests"])
        return request_ids
