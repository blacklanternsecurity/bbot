import multiprocessing

from .base import BaseModule

from badsecrets.base import carve_all_modules


class badsecrets(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {
        "description": "Library for detecting known or weak secrets across many web frameworks",
        "created_date": "2022-11-19",
        "author": "@liquidsec",
    }
    deps_pip = ["badsecrets~=0.4.490"]

    @property
    def _max_event_handlers(self):
        return max(1, multiprocessing.cpu_count() - 1)

    async def handle_event(self, event):
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
            try:
                r_list = await self.scan.run_in_executor_mp(
                    carve_all_modules,
                    body=resp_body,
                    headers=resp_headers,
                    cookies=resp_cookies,
                    url=event.data.get("url", None),
                )
            except Exception as e:
                self.warning(f"Error processing {event}: {e}")
                return
            if r_list:
                for r in r_list:
                    if r["type"] == "SecretFound":
                        data = {
                            "severity": r["description"]["severity"],
                            "description": f"Known Secret Found. Secret Type: [{r['description']['secret']}] Secret: [{r['secret']}] Product Type: [{r['description']['product']}] Product: [{self.helpers.truncate_string(r['product'],2000)}] Detecting Module: [{r['detecting_module']}] Details: [{r['details']}]",
                            "url": event.data["url"],
                            "host": str(event.host),
                        }
                        await self.emit_event(data, "VULNERABILITY", event)
                    elif r["type"] == "IdentifyOnly":
                        # There is little value to presenting a non-vulnerable asp.net viewstate, as it is not crackable without a Matrioshka brain. Just emit a technology instead.
                        if r["detecting_module"] == "ASPNET_Viewstate":
                            await self.emit_event(
                                {"technology": "microsoft asp.net", "url": event.data["url"], "host": str(event.host)},
                                "TECHNOLOGY",
                                event,
                            )
                        else:
                            data = {
                                "description": f"Cryptographic Product identified. Product Type: [{r['description']['product']}] Product: [{self.helpers.truncate_string(r['product'],2000)}] Detecting Module: [{r['detecting_module']}]",
                                "url": event.data["url"],
                                "host": str(event.host),
                            }
                            await self.emit_event(data, "FINDING", event)
