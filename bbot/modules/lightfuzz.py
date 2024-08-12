from bbot.modules.base import BaseModule
import statistics
import re
import os
import base64
import urllib.parse

from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, unquote
from bbot.errors import InteractshError, HttpCompareError

from .lightfuzz_submodules.cmdi import CmdILightfuzz
from .lightfuzz_submodules.crypto import CryptoLightfuzz
from .lightfuzz_submodules.path import PathTraversalLightfuzz
from .lightfuzz_submodules.sqli import SQLiLightfuzz
from .lightfuzz_submodules.ssti import SSTILightfuzz
from .lightfuzz_submodules.xss import XSSLightfuzz
from .lightfuzz_submodules.serial import SerialLightfuzz


class lightfuzz(BaseModule):
    watched_events = ["URL", "WEB_PARAMETER"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "web-thorough"]

    submodules = {
        "sqli": {"description": "SQL Injection", "module": SQLiLightfuzz},
        "cmdi": {"description": "Command Injection", "module": CmdILightfuzz},
        "xss": {"description": "Cross-site Scripting", "module": XSSLightfuzz},
        "path": {"description": "Path Traversal", "module": PathTraversalLightfuzz},
        "ssti": {"description": "Server-side Template Injection", "module": SSTILightfuzz},
        "crypto": {"description": "Cryptography Probe", "module": CryptoLightfuzz},
        "serial": {"description": "Unsafe Deserialization Probe", "module": SerialLightfuzz},
    }

    options = {"force_common_headers": False, "enabled_submodules": []}
    options_desc = {
        "force_common_headers": "Force emit commonly exploitable parameters that may be difficult to detect",
        "enabled_submodules": "A list of submodules to enable. Empty list enabled all modules.",
    }

    meta = {"description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner"}
    common_headers = ["x-forwarded-for", "user-agent"]
    parameter_blacklist = [
        "__VIEWSTATE",
        "__EVENTARGUMENT",
        "__EVENTVALIDATION",
        "__EVENTTARGET",
        "__EVENTARGUMENT",
        "__VIEWSTATEGENERATOR",
        "__SCROLLPOSITIONY",
        "__SCROLLPOSITIONX",
        "ASP.NET_SessionId",
        "JSESSIONID",
        "PHPSESSID",
        "__cf_bm",
    ]
    in_scope_only = True

    _module_threads = 4

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None
        self.enabled_submodules = self.config.get("enabled_submodules")

        for m in self.enabled_submodules:
            if m not in self.submodules:
                self.hugewarning(f"Invalid Lightfuzz submodule ({m}) specified in enabled_modules")
                return False

        for submodule, submodule_dict in self.submodules.items():
            if submodule in self.enabled_submodules or self.enabled_submodules == []:
                setattr(self, submodule, True)
                self.hugeinfo(f"Lightfuzz {submodule_dict['description']} Submodule Enabled")

                if submodule == "cmdi" and self.scan.config.get("interactsh_disable", False) == False:
                    try:
                        self.interactsh_instance = self.helpers.interactsh()
                        self.interactsh_domain = await self.interactsh_instance.register(
                            callback=self.interactsh_callback
                        )
                    except InteractshError as e:
                        self.warning(f"Interactsh failure: {e}")
            else:
                setattr(self, submodule, False)
        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                details = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not details["event"]:
                    return
                await self.emit_event(
                    {
                        "severity": "CRITICAL",
                        "host": str(details["event"].host),
                        "url": details["event"].data["url"],
                        "description": f"OS Command Injection (OOB Interaction) Type: [{details['type']}] Parameter Name: [{details['name']}] Probe: [{details['probe']}]",
                    },
                    "VULNERABILITY",
                    details["event"],
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    def _outgoing_dedup_hash(self, event):
        return hash(
            (
                "lightfuzz",
                str(event.host),
                event.data["url"],
                event.data["description"],
                event.data.get("type", ""),
                event.data.get("name", ""),
            )
        )

    def in_bl(self, value):
        in_bl = False
        for bl_param in self.parameter_blacklist:
            if bl_param.lower() == value.lower():
                in_bl = True
        return in_bl

    def url_unparse(self, param_type, parsed_url):
        if param_type == "GETPARAM":
            querystring = ""
        else:
            querystring = parsed_url.query
        return urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                "",
                querystring if self.retain_querystring else "",
                "",
            )
        )

    async def run_submodule(self, submodule, event):
        submodule_instance = submodule(self, event)
        await submodule_instance.fuzz()
        if len(submodule_instance.results) > 0:
            for r in submodule_instance.results:
                event_data = {"host": str(event.host), "url": event.data["url"], "description": r["description"]}
                if r["type"] == "VULNERABILITY":
                    event_data["severity"] = r["severity"]
                await self.emit_event(
                    event_data,
                    r["type"],
                    event,
                )

    async def handle_event(self, event):

        if event.type == "URL":
            if self.config.get("force_common_headers", False) == False:

                return False

            for h in self.common_headers:
                description = f"Speculative (Forced) Header [{h}]"
                data = {
                    "host": str(event.host),
                    "type": "HEADER",
                    "name": h,
                    "original_value": None,
                    "url": event.data,
                    "description": description,
                }
                await self.emit_event(data, "WEB_PARAMETER", event)

        elif event.type == "WEB_PARAMETER":

            # check connectivity to url
            connectivity_test = await self.helpers.request(event.data["url"], timeout=10)

            if connectivity_test:
                for submodule, submodule_dict in self.submodules.items():
                    if getattr(self, submodule):
                        self.debug(f"Starting {submodule_dict['description']} fuzz()")
                        await self.run_submodule(submodule_dict["module"], event)
            else:
                self.debug(f'WEB_PARAMETER URL {event.data["url"]} failed connectivity test, aborting')

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
