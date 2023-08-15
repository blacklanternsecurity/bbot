from .discord import Discord


class Teams(Discord):
    watched_events = ["*"]
    meta = {"description": "Message a Slack channel when certain events are encountered"}
    options = {"webhook_url": "", "event_types": ["VULNERABILITY"]}
    options_desc = {"webhook_url": "Discord webhook URL", "event_types": "Types of events to send"}
    max_event_handlers = 5
    good_status_code = 200
    content_key = "text"

    def evaluate_response(self, response):
        text = getattr(response, "text", "")
        return text == "1"
