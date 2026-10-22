from bbot.errors import HttpCompareError

from .base import BaseAccessBypass

# extensions tested as a query parameter value to probe extension-based routing
routing_extensions = [".css", ".js", ".xls", ".png", ".jpg", ".swf", ".xml", ".pdf", ".gif"]


class extension_routing(BaseAccessBypass):
    friendly_name = "URL Manipulation"
    severity = "INFO"
    # runs on reachable pages, not blocked ones
    trigger_status_codes = (200, 301, 302)

    async def run(self):
        rand_string = self.access_bypass.rand_string
        try:
            if not await self.compare_helper.canary_check(self.event.url, mode="getparam"):
                raise HttpCompareError()
        except HttpCompareError:
            self.access_bypass.verbose(f'Aborting "{self.event.url}" due to failed canary check')
            return

        path = self.parsed_url.path.lstrip("/")
        for ext in routing_extensions:
            url = f"{self.base_url}/{path}?{rand_string}={ext}"
            try:
                match, reasons, _, response = await self.compare_helper.compare(url, allow_redirects=True)
            except HttpCompareError as e:
                self.access_bypass.debug(f"Encountered HttpCompareError: [{e}] for URL [{self.event.url}]")
                continue

            if response is None:
                continue
            subject_content = response.raw_headers + (response.text or "")
            if rand_string in subject_content:
                self.access_bypass.debug("Ignoring positive result due to presence of parameter name in result")
                continue
            if match is False and str(response.status_code).startswith("2") and "body" in reasons:
                self.add_result(
                    f"{self.friendly_name}: [{','.join(reasons)}] Sig: [Modified URL: {url}]",
                    confidence="LOW",
                )
