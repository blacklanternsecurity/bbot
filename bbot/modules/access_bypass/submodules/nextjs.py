import re
import json
from contextlib import suppress

from .base import BaseAccessBypass

# redirect targets that look like an auth gate
auth_redirect_regex = re.compile(r"/(auth|login|signin|sign-in|sso)(/|\?|$)", re.I)
# __NEXT_DATA__ carries the deploy's buildId; it changes on every deploy
build_id_regex = re.compile(r'"buildId"\s*:\s*"([^"]+)"')
# common Next.js locale prefixes for data routes
locales = ["", "/en-US", "/en"]


class nextjs(BaseAccessBypass):
    friendly_name = "Next.js Data Route Auth Bypass"
    severity = "HIGH"
    trigger_status_codes = (200, 301, 302, 307, 308)

    def applies(self):
        status = self.event.http_status
        if status == 200:
            return True
        return status in (301, 302, 307, 308) and bool(auth_redirect_regex.search(self.event.redirect_location))

    @property
    def build_ids(self):
        return self.access_bypass.submodule_state.setdefault("nextjs_build_ids", {})

    async def run(self):
        host = self.parsed_url.netloc
        if self.event.http_status == 200:
            await self.harvest_build_id(host, self.event.url)
            return

        build_id = self.build_ids.get(host)
        if build_id is None:
            build_id = await self.harvest_build_id(host, f"{self.base_url}/")
        if not build_id:
            return

        path = self.parsed_url.path
        for locale in locales:
            data_url = f"{self.base_url}/_next/data/{build_id}{locale}{path}.json"
            response = await self.helpers.request(data_url, headers={"x-nextjs-data": "1"})
            if response is None or response.status_code != 200:
                continue
            page_props = self.extract_page_props(response.text or "")
            if page_props is not None:
                self.add_result(
                    f"{self.friendly_name}: {self.event.url} redirects to "
                    f"{self.event.redirect_location}, but its data route {data_url} returned page data unauthenticated",
                    confidence="HIGH",
                    url=data_url,
                )
                return

    async def harvest_build_id(self, host, url):
        if host in self.build_ids:
            return self.build_ids[host]
        response = await self.helpers.request(url)
        build_id = None
        if response is not None and response.text:
            match = build_id_regex.search(response.text)
            if match:
                build_id = match.group(1)
        self.build_ids[host] = build_id
        return build_id

    @staticmethod
    def extract_page_props(text):
        """Return the pageProps dict if the body is a Next.js data payload that was NOT redirected."""
        with suppress(ValueError):
            data = json.loads(text)
            if not isinstance(data, dict):
                return None
            page_props = data.get("pageProps")
            if page_props is None:
                return None
            # middleware redirected/404'd the data route too — not a bypass
            if "__N_REDIRECT" in page_props or "__N_NOTFOUND" in page_props:
                return None
            return page_props
        return None
