import asyncio

from bbot.modules.base import BaseModule


class snovio(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query Snov.io Domain Search v2 for company email addresses",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {"client_id": "", "client_secret": "", "max_pages": 3, "max_polls": 8, "poll_interval": 1}
    options_desc = {
        "client_id": "Snov.io OAuth client_id",
        "client_secret": "Snov.io OAuth client_secret",
        "max_pages": "Maximum number of paginated email-result pages to retrieve",
        "max_polls": "Maximum number of polling attempts per task while status is in_progress",
        "poll_interval": "Seconds between polling attempts",
    }

    oauth_url = "https://api.snov.io/v1/oauth/access_token"
    start_url = "https://api.snov.io/v2/domain-search/domain-emails/start"
    result_url_template = "https://api.snov.io/v2/domain-search/domain-emails/result/{task_hash}"

    per_domain_only = True

    async def setup(self):
        self.client_id = self.config.get("client_id", "")
        self.client_secret = self.config.get("client_secret", "")
        self.max_pages = max(1, int(self.config.get("max_pages", 3)))
        self.max_polls = max(1, int(self.config.get("max_polls", 8)))
        self.poll_interval = max(0, int(self.config.get("poll_interval", 1)))
        self.access_token = ""

        if not self.client_id or not self.client_secret:
            return None, "Must set client_id and client_secret"

        if not await self.refresh_token():
            return None, "Failed to retrieve Snov.io access token"
        return True

    async def refresh_token(self):
        response = await self.helpers.request(
            self.oauth_url,
            method="POST",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        token_json = self._safe_json(response)
        self.access_token = str(token_json.get("access_token", "")).strip()
        return bool(self.access_token)

    @property
    def auth_headers(self):
        return {"Authorization": f"Bearer {self.access_token}"}

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        if not query:
            return

        emitted = set()
        next_token = ""
        pages = 0
        while pages < self.max_pages:
            start_json = await self.start_domain_emails_task(query, next_token=next_token)
            if not start_json:
                break

            links = start_json.get("links", {})
            meta = start_json.get("meta", {})
            task_hash = str(meta.get("task_hash", "")).strip()
            result_url = str(links.get("result", "")).strip()
            if not result_url and task_hash:
                result_url = self.result_url_template.format(task_hash=task_hash)
            if not result_url:
                break

            result_json = await self.poll_results(result_url)
            if not result_json:
                break

            for row in result_json.get("data", []):
                if not isinstance(row, dict):
                    continue
                email = str(row.get("email", "")).strip().lower()
                if not email or email in emitted:
                    continue
                email_event = self.make_event(email, "EMAIL_ADDRESS", parent=event)
                if email_event is not None:
                    emitted.add(email)
                    await self.emit_event(
                        email_event,
                        context=f'{{module}} searched Snov.io Domain Search for "{query}" and found {{event.type}}: {{event.data}}',
                    )

            next_token = str(result_json.get("meta", {}).get("next", "")).strip()
            pages += 1
            if not next_token:
                break

    async def start_domain_emails_task(self, domain, next_token=""):
        data = {"domain": domain}
        if next_token:
            data["next"] = next_token
        response = await self.helpers.request(self.start_url, method="POST", headers=self.auth_headers, data=data)
        if getattr(response, "status_code", 0) == 401 and await self.refresh_token():
            response = await self.helpers.request(self.start_url, method="POST", headers=self.auth_headers, data=data)
        return self._safe_json(response)

    async def poll_results(self, result_url):
        result_json = {}
        for attempt in range(self.max_polls):
            response = await self.helpers.request(result_url, method="GET", headers=self.auth_headers)
            if getattr(response, "status_code", 0) == 401 and await self.refresh_token():
                response = await self.helpers.request(result_url, method="GET", headers=self.auth_headers)
            result_json = self._safe_json(response)
            status = str(result_json.get("status", "")).strip().lower()
            if status != "in_progress":
                return result_json
            if attempt < self.max_polls - 1 and self.poll_interval > 0:
                await asyncio.sleep(self.poll_interval)
        return result_json

    def _safe_json(self, response):
        if response is None:
            return {}
        if getattr(response, "status_code", 0) != 200:
            self.verbose(f"Snov.io returned HTTP status {getattr(response, 'status_code', 0)}")
            return {}
        try:
            parsed = response.json()
        except Exception:
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}
