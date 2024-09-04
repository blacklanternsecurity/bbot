import yaml

from bbot.modules.templates.webhook import WebhookOutputModule


class Slack(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Slack channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }
    options = {"webhook_url": "", "event_types": ["VULNERABILITY", "FINDING"], "min_severity": "LOW"}
    options_desc = {
        "webhook_url": "Discord webhook URL",
        "event_types": "Types of events to send",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
    }
    content_key = "text"

    def format_message_str(self, event):
        event_tags = ",".join(sorted(event.tags))
        return f"`[{event.type}]`\t*`{event.data}`*\t`{event_tags}`"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"*`[{event.type}]`*"
        if event.type in ("VULNERABILITY", "FINDING"):
            event_str, color = self.get_severity_color(event)
            event_type = f"{color} `{event_str}` {color}"
        return f"""*{event_type}*\n```\n{event_yaml}```"""
