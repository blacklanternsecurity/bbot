from bbot.modules.base import BaseModule


class nowafpls(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "invasive", "web-heavy"]
    meta = {
        "description": "Detect WAF bypasses via HTTP body padding (nowafpls technique)",
        "created_date": "2026-07-14",
        "author": "@liquidsec",
    }

    per_host_only = True
    in_scope_only = True

    async def filter_event(self, event):
        if "waf" not in event.tags:
            return False, "target is not tagged as behind a WAF"
        if any(t.startswith("status-3") for t in event.tags):
            return False, "URL is a redirect; padding probe would target the redirect, not the app"
        return True

    async def handle_event(self, event):
        result = await self.helpers.nowafpls.is_bypassable(event)
        if not result.bypassed:
            self.verbose(f"No bypass finding for {event.url}: {result.summary}")
            return

        provider = result.waf_provider or "WAF/inspection layer"
        await self.emit_event(
            {
                "host": str(event.host),
                "url": event.url,
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "name": "WAF Bypass via Body Padding",
                "description": (
                    f"{provider} bypassable via nowafpls-style body padding "
                    f"(padding size: {result.padding_size} bytes)."
                ),
            },
            "FINDING",
            parent=event,
            context=(
                f"{{module}} bypassed the WAF at {event.url} via {result.padding_size}-byte body padding. "
                f"Unpadded malicious POST diverged from the baseline; the padded POST converged back, "
                f"indicating the payload reached the application past the inspection layer."
            ),
        )
