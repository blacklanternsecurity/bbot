from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
import math


class trickest(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Trickest's API for subdomains",
        "author": "@YourUsername",
        "created_date": "2024-07-27",
        "auth_required": True,
    }
    options = {
        "api_key": "",
    }
    options_desc = {
        "api_key": "Trickest API key",
    }

    base_url = "https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/view"
    dataset_id = "a0a49ca9-03bb-45e0-aa9a-ad59082ebdfc"

    async def setup(self):
        self.api_key = self.config.get("api_key", "").strip()
        self.headers = {"Authorization": f"Token {self.api_key}"}
        return await super().setup()

    async def ping(self):
        if not self.api_key:
            return False
        url = f"{self.base_url}?dataset_id={self.dataset_id}&limit=1"
        try:
            response = await self.helpers.request(url, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            self.error(f"Ping failed: {str(e)}")
            return False

    async def get_total_count(self, query):
        params = {
            "offset": 0,
            "limit": 1,
            "dataset_id": self.dataset_id,
            "q": f'hostname ~ "{query}"',
            "select": "hostname",
            "orderby": "hostname",
        }
        response = await self.helpers.request(self.base_url, headers=self.headers, params=params)
        if response and response.status_code == 200:
            return response.json().get("total_count", 0)
        return 0

    async def request_url(self, query, offset):
        params = {
            "offset": offset,
            "limit": 100,
            "dataset_id": self.dataset_id,
            "q": f'hostname ~ "{query}"',
            "select": "hostname",
            "orderby": "hostname",
        }
        return await self.helpers.request(self.base_url, headers=self.headers, params=params)

    async def handle_event(self, event):
        query = self.make_query(event)
        total_count = await self.get_total_count(query)
        total_pages = math.ceil(total_count / 100)

        for page in range(total_pages):
            offset = page * 100
            response = await self.request_url(query, offset)
            if response and response.status_code == 200:
                for hostname in self.parse_results(response, query):
                    if hostname == event.data:
                        continue
                    tags = []
                    if not hostname.endswith(f".{query}"):
                        tags = ["affiliate"]
                    await self.emit_event(hostname, "DNS_NAME", event, tags=tags)
            else:
                self.error(f"Failed to fetch results for page {page + 1}")

        self.info(f"Processed {total_count} results for {query}")

    def parse_results(self, r, query):
        json_data = r.json()
        results = json_data.get("results", [])
        for item in results:
            hostname = item.get("hostname")
            if hostname:
                yield hostname
