import yaml

from bbot.modules.templates.webhook import WebhookOutputModule


class Slack(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Slack channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }
    options = {"webhook_url": "", "event_types": ["FINDING"], "min_severity": "LOW", "retries": 10}
    options_desc = {
        "webhook_url": "Discord webhook URL",
        "event_types": "Types of events to send",
        "min_severity": "Only allow FINDING events of this severity or higher",
        "retries": "Number of times to retry sending the message before skipping the event",
    }
    content_key = "text"

    def format_message_str(self, event):
        event_tags = ",".join(sorted(event.tags))
        return f"`[{event.type}]`\t*`{event.data}`*\t`{event_tags}`"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"*`[{event.type}]`*"
        event_str, severity_color, confidence_color = self.get_colors(event)
        event_type = f"Severity: {severity_color} Confidence: {confidence_color} {event_str}"
        return f"""*{event_type}*\n```\n{event_yaml}```"""
