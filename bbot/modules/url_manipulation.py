from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule


class url_manipulation(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Attempt to identify URL parsing/routing based vulnerabilities",
        "created_date": "2022-09-27",
        "author": "@liquidsec",
    }
    in_scope_only = True

    options = {"allow_redirects": True}
    options_desc = {
        "allow_redirects": "Allowing redirects will sometimes create false positives. Disallowing will sometimes create false negatives. Allowed by default."
    }

    async def setup(self):
        # ([string]method,[string]path,[bool]strip trailing slash)
        self.signatures = []

        self.rand_string = self.helpers.rand_string()

        # Test for abuse of extension based routing
        extensions = [
            ".css",
            ".js",
            ".xls",
            ".png",
            ".jpg",
            ".swf",
            ".xml",
            ".pdf",
            ".gif",
        ]
        for ext in extensions:
            self.signatures.append(("GET", "{scheme}://{netloc}/{path}?%s=%s" % (self.rand_string, ext), False))

        self.allow_redirects = self.config.get("allow_redirects", True)
        return True

    async def handle_event(self, event):
        try:
            compare_helper = self.helpers.http_compare(
                event.data, allow_redirects=self.allow_redirects, include_cache_buster=False
            )
        except HttpCompareError as e:
            self.debug(e)
            return

        try:
            if not await compare_helper.canary_check(event.data, mode="getparam"):
                raise HttpCompareError()
        except HttpCompareError:
            self.verbose(f'Aborting "{event.data}" due to failed canary check')
            return

        for sig in self.signatures:
            sig = self.format_signature(sig, event)
            try:
                match, reasons, reflection, subject_response = await compare_helper.compare(
                    sig[1], method=sig[0], allow_redirects=self.allow_redirects
                )
            except HttpCompareError as e:
                self.debug(f"Encountered HttpCompareError: [{e}] for URL [{event.data}]")

            if subject_response:
                subject_content = "".join([str(x) for x in subject_response.headers])
                if subject_response.text is not None:
                    subject_content += subject_response.text

                if self.rand_string not in subject_content:
                    if match is False:
                        if str(subject_response.status_code).startswith("2"):
                            if "body" in reasons:
                                reported_signature = f"Modified URL: {sig[1]}"
                                description = f"Url Manipulation: [{','.join(reasons)}] Sig: [{reported_signature}]"
                                await self.emit_event(
                                    {"description": description, "host": str(event.host), "url": event.data},
                                    "FINDING",
                                    parent=event,
                                    context=f"{{module}} probed {event.data} and identified {{event.type}}: {description}",
                                )
                        else:
                            self.debug(f"Status code changed to {str(subject_response.status_code)}, ignoring")
                else:
                    self.debug("Ignoring positive result due to presence of parameter name in result")

    async def filter_event(self, event):
        accepted_status_codes = ["200", "301", "302"]

        for c in accepted_status_codes:
            if f"status-{c}" in event.tags:
                return True
        return False

    def format_signature(self, sig, event):
        if sig[2] is True:
            cleaned_path = event.parsed_url.path.strip("/")
        else:
            cleaned_path = event.parsed_url.path.lstrip("/")

        kwargs = {"scheme": event.parsed_url.scheme, "netloc": event.parsed_url.netloc, "path": cleaned_path}
        formatted_url = sig[1].format(**kwargs)
        return (sig[0], formatted_url)
