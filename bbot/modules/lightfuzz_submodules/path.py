from .base import BaseLightfuzz

import urllib.parse

class PathTraversalLightfuzz(BaseLightfuzz):

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        if (
            "original_value" in self.event.data
            and self.event.data["original_value"] is not None
            and self.event.data["original_value"] != "1"
        ):
            probe_value = self.event.data["original_value"]
        else:
            self.lightfuzz.debug(
                f"Path Traversal detection requires original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        # Single dot traversal tolerance test

        path_techniques = {
            "single-dot traversal tolerance (no-encoding)": {
                "singledot_payload": f"/./{probe_value}",
                "doubledot_payload": f"/../{probe_value}",
            },
            "single-dot traversal tolerance (url-encoding)": {
                "singledot_payload": urllib.parse.quote(f"/./{probe_value}".encode(), safe=""),
                "doubledot_payload": urllib.parse.quote(f"/../{probe_value}".encode(), safe=""),
            },
        }

        for path_technique, payloads in path_techniques.items():

            try:
                singledot_probe = await self.compare_probe(
                    http_compare, self.event.data["type"], payloads["singledot_payload"], cookies
                )
                doubledot_probe = await self.compare_probe(
                    http_compare, self.event.data["type"], payloads["doubledot_payload"], cookies
                )

                if (
                    singledot_probe[0] == True
                    and doubledot_probe[0] == False
                    and doubledot_probe[3] != None
                    and not str(doubledot_probe[3].status_code).startswith("4")
                    and doubledot_probe[1] != ["header"]
                ):
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"POSSIBLE Path Traversal. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [{path_technique}]",
                        }
                    )
                    # no need to report both techniques if they both work
                    break
            except HttpCompareError as e:
                self.lightfuzz.debug(e)
                continue

        # Absolute path test

        absolute_paths = {r"c:\\windows\\win.ini": "; for 16-bit app support", "/etc/passwd": "daemon:x:"}

        for path, trigger in absolute_paths.items():
            r = await self.standard_probe(self.event.data["type"], cookies, path)
            if r and trigger in r.text:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Path Traversal. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Absolute Path: {path}]",
                    }
                )



