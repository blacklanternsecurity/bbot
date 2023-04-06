from .base import BaseModule

from badsecrets.base import carve_all_modules


class badsecrets(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {"description": "Library for detecting known or weak secrets across many web frameworks"}
    max_event_handlers = 2
    deps_pip = ["badsecrets~=0.1.279"]

    def handle_event(self, event):
        resp_body = event.data.get("body", None)
        resp_headers = event.data.get("header", None)
        resp_cookies = {}
        if resp_headers:
            resp_cookies_raw = resp_headers.get("set_cookie", None)
            if resp_cookies_raw:
                if "," in resp_cookies_raw:
                    resp_cookies_list = resp_cookies_raw.split(",")
                else:
                    resp_cookies_list = [resp_cookies_raw]
                for c in resp_cookies_list:
                    c2 = c.lstrip(";").strip().split(";")[0].split("=")
                    if len(c2) == 2:
                        resp_cookies[c2[0]] = c2[1]
        if resp_body or resp_cookies:
            r_list = carve_all_modules(body=resp_body, cookies=resp_cookies)
            if r_list:
                for r in r_list:
                    if r["type"] == "SecretFound":
                        data = {
                            "severity": "HIGH",
                            "description": f"Known Secret Found. Secret Type: [{r['description']['Secret']}] Secret: [{r['secret']}] Product Type: [{r['description']['Product']}] Product: [{r['source']}] Detecting Module: [{r['detecting_module']}]",
                            "url": event.data["url"],
                            "host": str(event.host),
                        }
                        self.emit_event(data, "VULNERABILITY", event)
                    elif r["type"] == "IdentifyOnly":
                        data = {
                            "description": f"Cryptographic Product identified. Product Type: [{r['description']['Product']}] Product: [{r['source']}] Detecting Module: [{r['detecting_module']}]",
                            "url": event.data["url"],
                            "host": str(event.host),
                        }
                        self.emit_event(data, "FINDING", event)
