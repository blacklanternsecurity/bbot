from .base import BaseLightfuzz
from bbot.errors import HttpCompareError

from urllib.parse import quote


class path(BaseLightfuzz):
    """
    Detects path traversal and local file inclusion vulnerabilities

    Techniques:

    * Relative Path Traversal:
       - Tests various relative path traversal patterns (../, ./, .../, etc.)
       - Uses multiple encoding variations (URL encoding, double encoding)
       - Attempts various path validation bypass techniques

    * Absolute Path Traversal:
       - Tests absolute paths for Windows (c:\\windows\\win.ini)
       - Tests absolute paths for Unix (/etc/passwd)
       - Tests null byte injection for extension bypass (%00)

    Results are validated using multiple confirmations and WAF response filtering to eliminate false positives.
    """

    friendly_name = "Path Traversal"

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.incoming_probe_value(populate_empty=False)
        if not probe_value:
            self.debug(
                f"Path Traversal detection requires original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        # Single dot traversal tolerance test
        path_techniques = {
            "single-dot traversal tolerance (no-encoding)": {
                "singledot_payload": f"./a/../{probe_value}",
                "doubledot_payload": f"../a/../{probe_value}",
            },
            "single-dot traversal tolerance (no-encoding, leading slash)": {
                "singledot_payload": f"/./a/../{probe_value}",
                "doubledot_payload": f"/../a/../{probe_value}",
            },
            "single-dot traversal tolerance (url-encoding)": {
                "singledot_payload": quote(f"./a/../{probe_value}".encode(), safe=""),
                "doubledot_payload": quote(f"../a/../{probe_value}".encode(), safe=""),
            },
            "single-dot traversal tolerance (url-encoding, leading slash)": {
                "singledot_payload": quote(f"/./a/../{probe_value}".encode(), safe=""),
                "doubledot_payload": quote(f"/../a/../{probe_value}".encode(), safe=""),
            },
            "single-dot traversal tolerance (non-recursive stripping)": {
                "singledot_payload": f"...//a/....//{probe_value}",
                "doubledot_payload": f"....//a/....//{probe_value}",
            },
            "single-dot traversal tolerance (non-recursive stripping, leading slash)": {
                "singledot_payload": f"/...//a/....//{probe_value}",
                "doubledot_payload": f"/....//a/....//{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding)": {
                "singledot_payload": f".%252fa%252f..%252f{probe_value}",
                "doubledot_payload": f"..%252fa%252f..%252f{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding, leading slash)": {
                "singledot_payload": f"%252f.%252fa%252f..%252f{probe_value}",
                "doubledot_payload": f"%252f..%252fa%252f..%252f{probe_value}",
            },
        }

        compiled_regex = self.lightfuzz.helpers.re.compile(r"/(?:[\w-]+/)*[\w-]+\.\w+")
        linux_path_regex = await self.lightfuzz.helpers.re.match(compiled_regex, probe_value)
        if linux_path_regex is not None:
            original_path_only = "/".join(probe_value.split("/")[:-1])
            original_filename_only = probe_value.split("/")[-1]
            # Some servers validate the start of the path, so we construct our payload with the original path and filename
            path_techniques["single-dot traversal tolerance (start of path validation)"] = {
                "singledot_payload": f"{original_path_only}/./{original_filename_only}",
                "doubledot_payload": f"{original_path_only}/../{original_filename_only}",
            }

        for path_technique, payloads in path_techniques.items():
            iterations = 5  # one failed detection is tolerated, as long as its not the first run
            confirmations = 0
            while iterations > 0:
                try:
                    http_compare = self.compare_baseline(
                        self.event.data["type"], probe_value, cookies, skip_urlencoding=True
                    )
                    singledot_probe = await self.compare_probe(
                        http_compare,
                        self.event.data["type"],
                        payloads["singledot_payload"],
                        cookies,
                        skip_urlencoding=True,
                    )
                    doubledot_probe = await self.compare_probe(
                        http_compare,
                        self.event.data["type"],
                        payloads["doubledot_payload"],
                        cookies,
                        skip_urlencoding=True,
                    )
                    # if singledot_probe[0] is true, the response is the same as the baseline. This indicates adding a single dot did not break the functionality
                    # next, if doubledot_probe[0] is false, the response is different from the baseline. This further indicates that a real path is being manipulated
                    # if doubledot_probe[3] is not None, the response is not empty.
                    # if doubledot_probe[1] is not ["header"], the response is not JUST a header change.
                    # "The requested URL was rejected" is a very common WAF error message which appears on 200 OK response, confusing detections
                    if (
                        singledot_probe[0] is True
                        and doubledot_probe[0] is False
                        and doubledot_probe[3] is not None
                        and doubledot_probe[1] != ["header"]
                        and "The requested URL was rejected" not in doubledot_probe[3].text
                    ):
                        confirmations += 1
                        self.verbose(f"Got possible Path Traversal detection: [{str(confirmations)}] Confirmations")
                        # only report if we have 3 confirmations
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
                    self.debug(e)
                    continue

                iterations -= 1
                if confirmations == 0:
                    break

        # Absolute path test, covering Windows and Linux
        absolute_paths = {
            r"c:\\windows\\win.ini": "; for 16-bit app support",
            "/etc/passwd": "daemon:x:",
            "../../../../../etc/passwd%00.png": "daemon:x:",
        }

        for path, trigger in absolute_paths.items():
            r = await self.standard_probe(self.event.data["type"], cookies, path, skip_urlencoding=True)
            if r and trigger in r.text:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Path Traversal. {self.metadata()} Detection Method: [Absolute Path: {path}]",
                    }
                )
