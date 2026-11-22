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
                if not await self.routes_again(url, path, rand_string):
                    self.access_bypass.debug(f"Rejecting {url}: the page changes without the extension too")
                    continue
                self.add_result(await self.describe(f"Modified URL: {url}", reasons, response), confidence="LOW")

    async def routes_again(self, url, path, rand_string):
        """
        Whether the page keeps answering without the extension as it did at baseline, while `url` differs again: a
        routing rule answers the same way every time, where a page that changes on its own differs now and then.
        """
        if await self.page_changed(path, rand_string):
            return False
        try:
            match, reasons, _, response = await self.compare_helper.compare(url, allow_redirects=True)
        except HttpCompareError:
            return False
        if response is None or match is not False or "body" not in reasons:
            return False
        return not await self.page_changed(path, rand_string)

    async def page_changed(self, path, rand_string):
        """
        Whether the page now differs from its baseline with the same parameter and no extension in it: content that
        changes over time, or a block that starts partway through, rather than routing by extension.
        """
        control = f"{self.base_url}/{path}?{rand_string}={self.helpers.rand_string(6)}"
        try:
            match, reasons, _, response = await self.compare_helper.compare(control, allow_redirects=True)
        except HttpCompareError:
            return True
        return response is None or (match is False and "body" in reasons)
