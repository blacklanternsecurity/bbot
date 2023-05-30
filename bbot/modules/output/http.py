from bbot.core.errors import RequestError

from bbot.modules.output.base import BaseOutputModule


class HTTP(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Send every event to a custom URL via a web request"}
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
            try:
                await self.helpers.request(
                    url=self.url,
                    method=self.method,
                    auth=self.auth,
                    headers=self.headers,
                    json=dict(event),
                    raise_error=True,
                )
                break
            except RequestError as e:
                self.warning(f"Error sending {event}: {e}, retrying...")
                await self.helpers.sleep(1)
