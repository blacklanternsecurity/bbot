from bbot.modules.templates.webhook import WebhookOutputModule


class Teams(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Teams channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }
    options = {"webhook_url": "", "event_types": ["VULNERABILITY", "FINDING"], "min_severity": "LOW"}
    options_desc = {
        "webhook_url": "Discord webhook URL",
        "event_types": "Types of events to send",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
    }
    _module_threads = 5
    good_status_code = 200
    content_key = "text"

    def evaluate_response(self, response):
        text = getattr(response, "text", "")
        return text == "1"
