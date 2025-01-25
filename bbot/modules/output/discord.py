from bbot.modules.templates.webhook import WebhookOutputModule


class Discord(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Discord channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }
    options = {"webhook_url": "", "event_types": ["VULNERABILITY", "FINDING"], "min_severity": "LOW", "retries": 10}
    options_desc = {
        "webhook_url": "Discord webhook URL",
        "event_types": "Types of events to send",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
        "retries": "Number of times to retry sending the message before skipping the event",
    }
