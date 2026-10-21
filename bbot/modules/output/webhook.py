from bbot.models.pydantic import Event
from bbot.modules.output.base import BaseOutputModule
from bbot.core.config.models import BaseModuleConfig, Field


class webhook(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Send every event to a custom URL via a webhook",
        "created_date": "2022-04-13",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        url: str = Field("", description="Web URL")
        method: str = Field("POST", description="HTTP method")
        bearer: str = Field("", description="Authorization Bearer token", sensitive=True)
        username: str = Field("", description="Username (basic auth)")
        password: str = Field("", description="Password (basic auth)", sensitive=True)
        headers: dict = Field({}, description="Additional headers to send with the request", sensitive=True)
        timeout: int = Field(10, description="HTTP timeout")
        ssl_verify: bool | None = Field(
            None, description="Verify SSL certificates (defaults to the global web.ssl_verify_infrastructure setting)"
        )

    async def setup(self):
        self.url = self.config.get("url", "")
        self.method = self.config.get("method", "POST")
        self.timeout = self.config.get("timeout", 10)
        self.ssl_verify = self.config.get("ssl_verify", None)
        if self.ssl_verify is None:
            self.ssl_verify = self.helpers.web.ssl_verify_infrastructure
        self.headers = dict(self.config.get("headers") or {})
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
        event_json = Event(**event.json()).model_dump(exclude_none=True)
        await self.api_request(
            url=self.url,
            method=self.method,
            auth=self.auth,
            headers=dict(self.headers),
            json=event_json,
            timeout=self.timeout,
            ssl_verify=self.ssl_verify,
        )
