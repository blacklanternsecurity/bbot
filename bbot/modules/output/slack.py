import yaml

from .discord import Discord


class Slack(Discord):
    watched_events = ["*"]
    meta = {"description": "Message a Slack channel when certain events are encountered"}
    options = {"webhook_url": "", "event_types": ["VULNERABILITY"]}
    options_desc = {"webhook_url": "Discord webhook URL", "event_types": "Types of events to send"}
    good_status_code = 200
    content_key = "text"

    def format_message_str(self, event):
        event_tags = ",".join(sorted(event.tags))
        return f"`[{event.type}]`\t*`{event.data}`*\t`{event_tags}`"

    def format_message_other(self, event):
        event_yaml = yaml.dump(event.data)
        event_type = f"*`[{event.type}]`*"
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "UNKNOWN")
            severity_color = event.severity_colors[severity]
            event_type = f"{severity_color} `{event.type} ({severity})` {severity_color}"
        return f"""*{event_type}*\n```\n{event_yaml}\n```"""
