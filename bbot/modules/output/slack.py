import yaml

from bbot.modules.templates.webhook import WebhookOutputModule
from bbot.core.config.models import BaseModuleConfig, Field


class Slack(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Slack channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        webhook_url: str = Field("", description="Slack webhook URL", sensitive=True)
        event_types: list[str] = Field(["FINDING"], description="Types of events to send")
        min_severity: str = Field("LOW", description="Only allow FINDING events of this severity or higher")
        retries: int = Field(10, description="Number of times to retry sending the message before skipping the event")

    content_key = "text"

    def format_message_str(self, event):
        event_tags = ",".join(sorted(event.tags))
        return f"`[{event.type}]`\t*`{event.pretty_string}`*\t`{event_tags}`"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"*`[{event.type}]`*"
        event_str, severity_color, confidence_color = self.get_colors(event)
        event_type = f"Severity: {severity_color} Confidence: {confidence_color} {event_str}"
        return f"""*{event_type}*\n```\n{event_yaml}```"""
