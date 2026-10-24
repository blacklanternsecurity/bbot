from urllib.parse import urlparse

import blasthttp

from bbot.modules.base import BaseModule
from bbot.core.helpers.web.response_event import response_to_event_dict


class browser_dom(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE", "URL_UNVERIFIED"]
    flags = ["active", "safe"]
    meta = {
        "description": "Load webpages in a real browser, emitting the DOM after scripts run and every URL the page requested",
        "created_date": "2026-10-23",
        "author": "@liquidsec",
    }
    browser_artifacts = ["dom", "network"]
    in_scope_only = True
    _module_threads = 4

    async def filter_event(self, event):
        if any(t.startswith("status-30") for t in event.tags):
            return False, "URL is a redirect"
        return True

    async def handle_event(self, event):
        url = event.url or event.data
        visit = await self.helpers.browser.visit(url, consumer=self.name)
        if visit is None:
            return
        if visit.response.conclusion[0] == "needs_browser":
            self.debug(f"Skipping {url}: the browser couldn't get past its challenge")
            return

        if visit.dom:
            # the same response, with the DOM as it stands after scripts ran in place of the body as served
            main = visit.response
            rendered = blasthttp.Response(
                main.url,
                main.status_code,
                headers=main.headers.items(),
                body=visit.dom,
                request_url=url,
                peer_ip=main.peer_ip,
            )
            rendered_event = self.make_event(
                response_to_event_dict(rendered, urlparse(url).netloc or url),
                "HTTP_RESPONSE",
                parent=event,
                tags=["browser-dom", f"status-{main.status_code}"],
                context="{module} loaded {event.parent.data} in a browser and got its rendered DOM",
            )
            if rendered_event is not None:
                # distinct id from the http module's response for the same URL, so dedup doesn't drop this
                rendered_event.reemit_source = "browser_dom"
                await self.emit_event(rendered_event)

        for request in visit.network:
            requested_url = request["url"]
            if not requested_url.startswith(("http://", "https://")) or requested_url == visit.response.url:
                continue
            await self.emit_event(
                requested_url,
                "URL_UNVERIFIED",
                parent=event,
                tags=[f"status-{request['status']}", "spider-danger"],
                context=f"{{module}} loaded {url} in a browser, which requested {{event.type}}: {requested_url}",
            )
