import re
from bbot.modules.base import BaseModule


class ajaxpro(BaseModule):

    ajaxpro_regex = re.compile(r'<script.+src="[\/a-zA-Z0-9\._]+,[a-zA-Z0-9\._]+\.ashx"')

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Check for potentially vulnerable Ajaxpro instances"}


	async def handle_event(self, event):

		resp_body = event.data.get("body", None)
        if resp_body:
    
            if event.type == "HTTP_RESPONSE":
                resp_body = event.data.get("body", None)
                if resp_body:
                    ajaxpro_regex_result = self.ajaxpro_regex.search(resp_body)
                    if ajaxpro_regex_result:
                        ajax_pro_path = m.group(0)
                        self.emit_event(
                            {
                                "host": str(event.host),
                                "url": event.data["url"],
                             "description": f"Ajaxpro Detected (Version Unconfirmed) Path: [{ajax_pro_path}]",
                            },
                            "FINDING",          
                            event,
                        )
