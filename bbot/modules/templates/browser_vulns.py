from bbot.modules.base import BaseModule


class browser_vulns(BaseModule):
    """
    A module that loads web pages in the scan's browser and reports the client-side vulnerabilities it finds in them.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]

    def _incoming_dedup_hash(self, event):
        # pages with the same body are the same page
        body_hash = event.data.get("hash", {}).get("body_sha256", "")
        if body_hash:
            return hash((event.host, body_hash)), f"body_sha256={body_hash}"
        return hash(event), ""

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            return False, "it isn't a 200"
        return True

    async def emit_finding(self, event, url, name, description, severity, confidence, context):
        await self.emit_event(
            {
                "name": name,
                "description": description,
                "host": str(event.host),
                "url": url,
                "severity": severity,
                "confidence": confidence,
            },
            "FINDING",
            event,
            context=context,
        )
