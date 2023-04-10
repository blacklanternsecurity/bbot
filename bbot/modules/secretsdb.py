import re
import yaml

from .base import BaseModule


class secretsdb(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {"description": "Detect common secrets with secrets-patterns-db"}
    options = {
        "min_confidence": 99,
        "signatures": "https://raw.githubusercontent.com/blacklanternsecurity/secrets-patterns-db/master/db/rules-stable.yml",
    }
    options_desc = {
        "min_confidence": "Only use signatures with this confidence score or higher",
        "signatures": "File path or URL to YAML signatures",
    }
    deps_pip = ["pyyaml~=6.0"]

    def setup(self):
        self.rules = []
        self.min_confidence = self.config.get("min_confidence", 99)
        self.sig_file = self.helpers.wordlist(self.config.get("signatures", ""))
        with open(self.sig_file) as f:
            rules_yaml = yaml.safe_load(f).get("patterns", [])
        for r in rules_yaml:
            r = r.get("pattern", {})
            if not r:
                continue
            name = r.get("name", "").lower()
            confidence = r.get("confidence", "")
            if name and confidence >= self.min_confidence:
                regex = r.get("regex", "")
                try:
                    compiled_regex = re.compile(regex)
                    r["regex"] = compiled_regex
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
                    matches = list(regex.finditer(text))
                    if matches:
                        matches = [m.string[m.start() : m.end()] for m in matches]
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
