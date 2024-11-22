from bbot.models.pydantic import Event
from bbot.modules.output.base import BaseOutputModule


class HTTP(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Send every event to a custom URL via a web request",
        "created_date": "2022-04-13",
        "author": "@TheTechromancer",
    }
    options = {
        "url": "",
        "method": "POST",
        "bearer": "",
        "username": "",
        "password": "",
        "timeout": 10,
    }
    options_desc = {
        "url": "Web URL",
        "method": "HTTP method",
        "bearer": "Authorization Bearer token",
        "username": "Username (basic auth)",
        "password": "Password (basic auth)",
        "timeout": "HTTP timeout",
    }

    async def setup(self):
        self.url = self.config.get("url", "")
        self.method = self.config.get("method", "POST")
        self.timeout = self.config.get("timeout", 10)
        self.headers = {}
        bearer = self.config.get("bearer", "")
        if bearer:
            self.headers["Authorization"] = f"Bearer {bearer}"
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        self.auth = None
        if username:
            self.auth = (username, password)
        if not self.url:
            self.warning("Must set URL")
            return False
        if not self.method:
            self.warning("Must set HTTP method")
            return False
        return True

    async def handle_event(self, event):
        while 1:
            event_json = event.json()
            event_pydantic = Event(**event_json)
            event_json = event_pydantic.model_dump(exclude_none=True)
            response = await self.helpers.request(
                url=self.url,
                method=self.method,
                auth=self.auth,
                headers=self.headers,
                json=event_json,
            )
            is_success = False if response is None else response.is_success
            if not is_success:
                status_code = getattr(response, "status_code", 0)
                self.warning(f"Error sending {event} (HTTP status code: {status_code}), retrying...")
                body = getattr(response, "text", "")
                self.debug(body)
                if status_code == 429:
                    sleep_interval = 10
                else:
                    sleep_interval = 1
                await self.helpers.sleep(sleep_interval)
                continue
            break
