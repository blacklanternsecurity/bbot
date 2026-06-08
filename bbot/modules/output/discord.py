from bbot.modules.templates.webhook import WebhookOutputModule
from bbot.core.config.models import BaseModuleConfig, Field


class Discord(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Discord channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        webhook_url: str = Field("", description="Discord webhook URL", sensitive=True)
        event_types: list[str] = Field(["FINDING"], description="Types of events to send")
        min_severity: str = Field("LOW", description="Only allow FINDING events of this severity or higher")
        retries: int = Field(10, description="Number of times to retry sending the message before skipping the event")
