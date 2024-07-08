import multiprocessing
from pathlib import Path
from .base import BaseModule
from badsecrets.base import carve_all_modules


class badsecrets(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Library for detecting known or weak secrets across many web frameworks",
        "created_date": "2022-11-19",
        "author": "@liquidsec",
    }
    options = {"custom_secrets": None}
    options_desc = {
        "custom_secrets": "Include custom secrets loaded from a local file",
    }
    deps_pip = ["badsecrets~=0.4.490"]

    async def setup(self):
        self.custom_secrets = None
        custom_secrets = self.config.get("custom_secrets", None)
        if custom_secrets:
            if Path(custom_secrets).is_file():
                self.custom_secrets = custom_secrets
                self.info(f"Successfully loaded secrets file [{custom_secrets}]")
            else:
                self.warning(f"custom secrets file [{custom_secrets}] is not valid")
                return None, "Custom secrets file not valid"
        return True

    @property
    def _module_threads(self):
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
                r_list = await self.helpers.run_in_executor_mp(
                    carve_all_modules,
                    body=resp_body,
                    headers=resp_headers,
                    cookies=resp_cookies,
                    url=event.data.get("url", None),
                    custom_resource=self.custom_secrets,
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
                        await self.emit_event(
                            data,
                            "VULNERABILITY",
                            event,
                            context=f'{{module}}\'s "{r["detecting_module"]}" module found known {r["description"]["product"]} secret ({{event.type}}): "{r["secret"]}"',
                        )
                    elif r["type"] == "IdentifyOnly":
                        # There is little value to presenting a non-vulnerable asp.net viewstate, as it is not crackable without a Matrioshka brain. Just emit a technology instead.
                        if r["detecting_module"] == "ASPNET_Viewstate":
                            technology = "microsoft asp.net"
                            await self.emit_event(
                                {"technology": technology, "url": event.data["url"], "host": str(event.host)},
                                "TECHNOLOGY",
                                event,
                                context=f"{{module}} identified {{event.type}}: {technology}",
                            )
                        else:
                            data = {
                                "description": f"Cryptographic Product identified. Product Type: [{r['description']['product']}] Product: [{self.helpers.truncate_string(r['product'],2000)}] Detecting Module: [{r['detecting_module']}]",
                                "url": event.data["url"],
                                "host": str(event.host),
                            }
                            await self.emit_event(
                                data,
                                "FINDING",
                                event,
                                context=f'{{module}} identified cryptographic product ({{event.type}}): "{r["description"]["product"]}"',
                            )
