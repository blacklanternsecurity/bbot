import re
from bbot.modules.base import BaseModule


class ajaxpro(BaseModule):
    """
    Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
    """

    ajaxpro_regex = re.compile(r'<script.+src="([\/a-zA-Z0-9\._]+,[a-zA-Z0-9\._]+\.ashx)"')
    watched_events = ["HTTP_RESPONSE", "URL"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {"description": "Check for potentially vulnerable Ajaxpro instances"}

    async def handle_event(self, event):
        if event.type == "URL":
            if "dir" not in event.tags:
                return False
            probe_url = f"{event.data}ajaxpro/whatever.ashx"
            probe = await self.helpers.request(probe_url)
            if probe:
                if probe.status_code == 200:
                    probe_confirm = await self.helpers.request(f"{event.data}a/whatever.ashx")
                    if probe_confirm:
                        if probe_confirm.status_code != 200:
                            await self.emit_event(
                                {
                                    "host": str(event.host),
                                    "url": event.data,
                                    "description": f"Ajaxpro Detected (Version Unconfirmed) Trigger: [{probe_url}]",
                                },
                                "FINDING",
                                event,
                            )

        elif event.type == "HTTP_RESPONSE":
            resp_body = event.data.get("body", None)
            if resp_body:
                ajaxpro_regex_result = self.ajaxpro_regex.search(resp_body)
                if ajaxpro_regex_result:
                    ajax_pro_path = ajaxpro_regex_result.group(0)
                    await self.emit_event(
                        {
                            "host": str(event.host),
                            "url": event.data["url"],
                            "description": f"Ajaxpro Detected (Version Unconfirmed) Trigger: [{ajax_pro_path}]",
                        },
                        "FINDING",
                        event,
                    )
