from bbot.modules.templates.webhook import WebhookOutputModule


class Teams(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Teams channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }
    options = {"webhook_url": "", "event_types": ["VULNERABILITY", "FINDING"], "min_severity": "LOW", "retries": 10}
    options_desc = {
        "webhook_url": "Teams webhook URL",
        "event_types": "Types of events to send",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
        "retries": "Number of times to retry sending the message before skipping the event",
    }

    async def handle_event(self, event):
        data = self.format_message(event)
        await self.api_request(
            url=self.webhook_url,
            method="POST",
            json=data,
        )

    def trim_message(self, message):
        if len(message) > self.message_size_limit:
            message = message[: self.message_size_limit - 3] + "..."
        return message

    def format_message_str(self, event):
        items = []
        msg = self.trim_message(event.data)
        items.append({"type": "TextBlock", "text": f"{msg}", "wrap": True})
        items.append({"type": "FactSet", "facts": [{"title": "Tags:", "value": ", ".join(event.tags)}]})
        return items

    def format_message_other(self, event):
        items = [{"type": "FactSet", "facts": []}]
        for key, value in event.data.items():
            if key != "severity":
                msg = self.trim_message(str(value))
                items[0]["facts"].append({"title": f"{key}:", "value": msg})
        return items

    def get_severity_color(self, event):
        color = "Accent"
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "INFO")
            if severity == "CRITICAL":
                color = "Attention"
            elif severity == "HIGH":
                color = "Attention"
            elif severity == "MEDIUM":
                color = "Warning"
            elif severity == "LOW":
                color = "Good"
        return color

    def format_message(self, event):
        adaptive_card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "msteams": {"width": "full"},
                        "body": [],
                    },
                }
            ],
        }
        heading = {"type": "TextBlock", "text": f"{event.type}", "wrap": True, "size": "Large", "style": "heading"}
        body = adaptive_card["attachments"][0]["content"]["body"]
        body.append(heading)
        if event.type in ("VULNERABILITY", "FINDING"):
            subheading = {
                "type": "TextBlock",
                "text": event.data.get("severity", "INFO"),
                "spacing": "None",
                "size": "Large",
                "wrap": True,
            }
            subheading["color"] = self.get_severity_color(event)
            body.append(subheading)
        main_text = {
            "type": "ColumnSet",
            "separator": True,
            "spacing": "Medium",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [],
                }
            ],
        }
        if isinstance(event.data, str):
            items = self.format_message_str(event)
        else:
            items = self.format_message_other(event)
        main_text["columns"][0]["items"] = items
        body.append(main_text)
        return adaptive_card
