import yaml

from bbot.modules.output.base import BaseOutputModule


class WebhookOutputModule(BaseOutputModule):
    """
    A template for webhook output modules such as Discord, Teams, and Slack
    """

    accept_dupes = False
    message_size_limit = 2000
    content_key = "content"
    vuln_severities = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # abort module after 10 failed requests (not including retries)
    _api_failure_abort_threshold = 10
    # retry each request up to 10 times, respecting the Retry-After header
    _default_api_retries = 10

    async def setup(self):
        self.webhook_url = self.config.get("webhook_url", "")
        self.min_severity = self.config.get("min_severity", "LOW").strip().upper()
        assert self.min_severity in self.vuln_severities, (
            f"min_severity must be one of the following: {','.join(self.vuln_severities)}"
        )
        self.allowed_severities = self.vuln_severities[self.vuln_severities.index(self.min_severity) :]
        if not self.webhook_url:
            self.warning("Must set Webhook URL")
            return False
        return await super().setup()

    @property
    def api_retries(self):
        return self.config.get("retries", self._default_api_retries)

    async def handle_event(self, event):
        message = self.format_message(event)
        data = {self.content_key: message}
        await self.api_request(
            url=self.webhook_url,
            method="POST",
            json=data,
        )

    def get_watched_events(self):
        if self._watched_events is None:
            event_types = self.config.get("event_types", ["VULNERABILITY"])
            if isinstance(event_types, str):
                event_types = [event_types]
            self._watched_events = set(event_types)
        return self._watched_events

    async def filter_event(self, event):
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "UNKNOWN")
            if severity not in self.allowed_severities:
                return False, f"{severity} is below min_severity threshold"
        return True

    def format_message_str(self, event):
        event_tags = ",".join(event.tags)
        return f"`[{event.type}]`\t**`{event.data}`**\ttags:{event_tags}"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"**`[{event.type}]`**"
        if event.type in ("VULNERABILITY", "FINDING"):
            event_str, color = self.get_severity_color(event)
            event_type = f"{color} {event_str} {color}"
        return f"""**`{event_type}`**\n```yaml\n{event_yaml}```"""

    def get_severity_color(self, event):
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "UNKNOWN")
            return f"{event.type} ({severity})", event.severity_colors[severity]
        else:
            return event.type, "🟦"

    def format_message(self, event):
        if isinstance(event.data, str):
            msg = self.format_message_str(event)
        else:
            msg = self.format_message_other(event)
        if len(msg) > self.message_size_limit:
            msg = msg[: self.message_size_limit - 3] + "..."
        return msg

    def evaluate_response(self, response):
        return getattr(response, "is_success", False)
