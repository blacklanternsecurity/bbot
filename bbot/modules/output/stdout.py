import json

from bbot.logger import log_to_stderr
from bbot.modules.output.base import BaseOutputModule


class Stdout(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to text", "created_date": "2024-04-03", "author": "@TheTechromancer"}
    options = {"format": "text", "event_types": [], "event_fields": [], "in_scope_only": False, "accept_dupes": True}
    options_desc = {
        "format": "Which text format to display, choices: text,json",
        "event_types": "Which events to display, default all event types",
        "event_fields": "Which event fields to display",
        "in_scope_only": "Whether to only show in-scope events",
        "accept_dupes": "Whether to show duplicate events, default True",
    }
    vuln_severity_map = {"LOW": "HUGEWARNING", "MEDIUM": "HUGEWARNING", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
    format_choices = ["text", "json"]

    async def setup(self):
        self.text_format = self.config.get("format", "text").strip().lower()
        if self.text_format not in self.format_choices:
            return (
                False,
                f'Invalid text format choice, "{self.text_format}" (choices: {",".join(self.format_choices)})',
            )
        self.accept_event_types = [str(s).upper() for s in self.config.get("event_types", [])]
        self.show_event_fields = [str(s) for s in self.config.get("event_fields", [])]
        self.in_scope_only = self.config.get("in_scope_only", False)
        self.accept_dupes = self.config.get("accept_dupes", False)
        return True

    async def filter_event(self, event):
        if self.accept_event_types:
            if event.type not in self.accept_event_types:
                return False, f'Event type "{event.type}" is not in the allowed event_types'
        return True

    async def handle_event(self, event):
        json_mode = "human" if self.text_format == "text" else "json"
        event_json = event.json(mode=json_mode)
        if self.show_event_fields:
            event_json = {k: str(event_json.get(k, "")) for k in self.show_event_fields}

        if self.text_format == "text":
            await self.handle_text(event, event_json)
        elif self.text_format == "json":
            await self.handle_json(event, event_json)

    async def handle_text(self, event, event_json):
        if self.show_event_fields:
            event_str = "\t".join([str(s) for s in event_json.values()])
        else:
            event_str = self.human_event_str(event)

        # log vulnerabilities in vivid colors
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "INFO")
            if severity in self.vuln_severity_map:
                loglevel = self.vuln_severity_map[severity]
                log_to_stderr(event_str, level=loglevel, logname=False)
        elif event.type == "FINDING":
            log_to_stderr(event_str, level="HUGEINFO", logname=False)

        print(event_str)

    async def handle_json(self, event, event_json):
        print(json.dumps(event_json))
