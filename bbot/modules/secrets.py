import re
import yaml

from .base import BaseModule


class secrets(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Detect common secrets with secrets-patterns-db"}

    deps_ansible = [
        {
            "name": "Download secrets-patterns-db",
            "git": {
                "repo": "https://github.com/mazen160/secrets-patterns-db",
                "dest": "#{BBOT_TOOLS}/secrets-patterns-db",
                "single_branch": True,
                "version": "561f2035be12dd0d52ab663cffa6168b700c330d",
            },
        }
    ]
    deps_pip = ["pyyaml"]

    def setup(self):
        templates_dir = self.helpers.tools_dir / "secrets-patterns-db"
        template_file = (templates_dir / "db" / "rules-stable.yml").resolve()
        assert template_file.is_file(), f"Could not find template at {template_file}"
        with open(template_file) as f:
            rules_yaml = yaml.safe_load(f).get("patterns", [])
        self.rules = []
        for r in rules_yaml:
            r = r.get("pattern", {})
            if not r:
                continue
            name = r.get("name", "").lower()
            confidence = r.get("confidence", "").lower()
            if name and confidence:
                regex = r.get("regex", "")
                try:
                    r["regex"] = re.compile(regex)
                    self.rules.append(r)
                except Exception:
                    self.debug(f"Error compiling regex: r'{regex}'")
        return True

    def handle_event(self, event):
        resp_body = event.data.get("body", "")
        resp_headers = event.data.get("raw_header", "")
        for r in self.rules:
            regex = r["regex"]
            name = r["name"]
            for text in (resp_body, resp_headers):
                if text:
                    matches = list(regex.findall(text))
                    if matches:
                        description = f"Possible secret ({name}): {matches}"
                        event_data = {"host": str(event.host), "description": description}
                        parsed_url = getattr(event, "parsed", None)
                        if parsed_url:
                            event_data["url"] = parsed_url.geturl()
                        self.emit_event(
                            event_data,
                            "FINDING",
                            source=event,
                        )
