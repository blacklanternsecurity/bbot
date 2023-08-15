import yaml

from bbot.modules.output.base import BaseOutputModule


class Discord(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Message a Discord channel when certain events are encountered"}
    options = {"webhook_url": "", "event_types": ["VULNERABILITY"]}
    options_desc = {"webhook_url": "Discord webhook URL", "event_types": "Types of events to send"}
    accept_dupes = False
    good_status_code = 204
    content_key = "content"

    async def setup(self):
        self.webhook_url = self.config.get("webhook_url", "")
        if not self.webhook_url:
            self.warning("Must set Webhook URL")
            return False
        return True

    async def handle_event(self, event):
        while 1:
            data = {self.content_key: self.format_message(event)}
            response = await self.helpers.request(
                url=self.webhook_url,
                method="POST",
                json=data,
            )
            status_code = getattr(response, "status_code", 0)
            if self.evaluate_response(response):
                break
            else:
                response_data = getattr(response, "text", "")
                try:
                    retry_after = response.json().get("retry_after", 1)
                except Exception:
                    retry_after = 1
                self.verbose(
                    f"Error sending {event}: status code {status_code}, response: {response_data}, retrying in {retry_after} seconds"
                )
                await self.helpers.sleep(retry_after)

    def get_watched_events(self):
        if self._watched_events is None:
            event_types = self.config.get("event_types", ["VULNERABILITY"])
            if isinstance(event_types, str):
                event_types = [event_types]
            self._watched_events = set(event_types)
        return self._watched_events

    def format_message_str(self, event):
        event_tags = ",".join(event.tags)
        return f"`[{event.type}]`\t**`{event.data}`**\ttags:{event_tags}"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"**`[{event.type}]`**"
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "UNKNOWN")
            severity_color = event.severity_colors[severity]
            event_type = f"{severity_color} {event.type} ({severity}) {severity_color}"
        return f"""**`{event_type}`**\n```yaml\n{event_yaml}\n```"""

    def format_message(self, event):
        if isinstance(event.data, str):
            return self.format_message_str(event)
        else:
            return self.format_message_other(event)

    def evaluate_response(self, response):
        status_code = getattr(response, "status_code", 0)
        return status_code == self.good_status_code
