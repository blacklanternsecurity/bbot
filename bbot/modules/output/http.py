import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

from bbot.modules.output.base import BaseOutputModule


class HTTP(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Send every event to a custom URL via a web request"}
    options = {
        "url": "",
        "method": "POST",
        "bearer": "",
        "username": "",
        "password": "",
        "timeout": 10,
    }
    options_desc = {
        "url": "Web URL",
        "method": "HTTP method",
        "bearer": "Authorization Bearer token",
        "username": "Username (basic auth)",
        "password": "Password (basic auth)",
        "timeout": "HTTP timeout",
    }

    def setup(self):
        self.session = requests.Session()
        if not self.config.get("url", ""):
            self.warning("Must set URL")
            return False
        if not self.config.get("method", ""):
            self.warning("Must set HTTP method")
            return False
        return True

    def handle_event(self, event):
        r = requests.Request(
            url=self.config.get("url"),
            method=self.config.get("method", "POST"),
        )
        r.headers["User-Agent"] = self.scan.useragent
        r.json = dict(event)
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        if username:
            r.auth = HTTPBasicAuth(username, password)
        bearer = self.config.get("bearer", "")
        if bearer:
            r.headers["Authorization"] = f"Bearer {bearer}"
        try:
            timeout = self.config.get("timeout", 10)
            self.session.send(r.prepare(), timeout=timeout)
        except RequestException as e:
            self.warning(f"Error sending {event}: {e}")
