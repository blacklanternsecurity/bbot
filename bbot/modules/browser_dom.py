import json
from urllib.parse import parse_qsl, urlparse

import blasthttp

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field
from bbot.core.helpers.web.browser import NETWORK_BODY_TYPES
from bbot.core.helpers.web.response_event import response_to_event_dict


class browser_dom(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE", "URL_UNVERIFIED", "WEB_PARAMETER"]
    flags = ["active", "safe"]
    meta = {
        "description": "Load webpages in a real browser, emitting the DOM after scripts run, the URLs they request "
        "and the parameters they send",
        "created_date": "2026-10-23",
        "author": "@liquidsec",
    }
    browser_artifacts = ["dom", "network"]
    in_scope_only = True
    _module_threads = 4

    class Config(BaseModuleConfig):
        parameters: bool = Field(
            True,
            description="Emit the parameters in the requests the page's scripts send (query, form and JSON), with "
            "the values, cookies and headers they were sent with, for modules that test parameters",
        )

    async def setup(self):
        # like excavate, only when a module in the scan tests parameters
        tests_parameters = any("WEB_PARAMETER" in m.watched_events for m in self.scan.modules.values())
        self.parameters = self.config.get("parameters", True) and tests_parameters
        # each parameter is emitted once, however many pages send it
        self.seen_parameters = set()
        return True

    async def filter_event(self, event):
        if any(t.startswith("status-30") for t in event.tags):
            return False, "URL is a redirect"
        return True

    async def handle_event(self, event):
        url = event.url or event.data
        visit = await self.browser_visit(event)
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
            tags = ["browser-dom", f"status-{main.status_code}"]
            if visit.redirect is not None:
                # the page tried to redirect itself; this is what it built before it would have left
                tags.append("js-redirect")
            rendered_event = self.make_event(
                response_to_event_dict(rendered, urlparse(url).netloc or url),
                "HTTP_RESPONSE",
                parent=event,
                tags=tags,
                context="{module} loaded {event.parent.data} in a browser and got its rendered DOM",
            )
            if rendered_event is not None:
                # distinct id from the http module's response for the same URL, so dedup doesn't drop this
                rendered_event.reemit_source = "browser_dom"
                await self.emit_event(rendered_event)

        # a page that sends itself elsewhere sends that request's parameters too, like a sign-in page sending its
        # visitor to an identity provider's authorize endpoint
        if self.parameters and visit.redirect is not None and visit.redirect[0] == "GET":
            redirect = {"url": visit.redirect[1], "method": "GET", "sent": {}, "content_type": None}
            await self.emit_parameters(event, url, redirect)

        for request in visit.network:
            requested_url = request["url"]
            if not requested_url.startswith(("http://", "https://")):
                continue
            # a script's request to the page's own URL still carries parameters
            if self.parameters and request["sent"] is not None:
                await self.emit_parameters(event, url, request)
            # the page itself, images, fonts and media aren't worth following, and a request that sent something isn't
            # a page to fetch
            if (
                requested_url == visit.response.url
                or request["resource_type"] not in NETWORK_BODY_TYPES
                or request["method"] != "GET"
            ):
                continue
            url_event = self.make_event(
                requested_url,
                "URL_UNVERIFIED",
                parent=event,
                tags=[f"status-{request['status']}", "spider-danger"],
                context=f"{{module}} loaded {url} in a browser, which requested {{event.type}}: {requested_url}",
            )
            if url_event is None:
                continue
            # the browser already has the response, so the http module uses it instead of fetching again
            url_event.prefetched_response = request["response"]
            await self.emit_event(url_event)

    async def emit_parameters(self, event, page_url, request):
        """
        Emit a WEB_PARAMETER for each parameter the page sent in `request`: in its query string, or, in a request with
        a body, in its form or JSON body, whose query stays on its URL. Each carries the other values, the cookies and
        the page's own headers it was sent with, and what the response was.
        """
        parsed = urlparse(request["url"])
        if not self.scan.in_scope(parsed.hostname):
            return
        sent = request["sent"]
        if request["method"] == "GET":
            parameter_type = "GETPARAM"
            values = self._first_values(parsed.query)
            parameter_url = parsed._replace(query="", fragment="").geturl()
        else:
            parameter_url = parsed._replace(fragment="").geturl()
            body_type = sent["content_type"].split(";")[0].strip().lower()
            if body_type == "application/x-www-form-urlencoded":
                parameter_type = "POSTPARAM"
                values = self._first_values(sent["body"] or "")
            elif body_type == "application/json" or body_type.endswith("+json"):
                parameter_type = "BODYJSON"
                try:
                    values = json.loads(sent["body"] or "")
                except ValueError:
                    return
                if not isinstance(values, dict):
                    return
            else:
                return

        for name, value in values.items():
            key = (parameter_type, parameter_url, name)
            if key in self.seen_parameters or self.helpers.web.parameter_blacklisted(name):
                continue
            self.seen_parameters.add(key)
            data = {
                "host": parsed.hostname,
                "type": parameter_type,
                "name": name,
                "original_value": value if isinstance(value, str) else json.dumps(value),
                "url": parameter_url,
                "description": f"HTTP Extracted Parameter [{name}] (Browser Request)",
                # the rest of the request as the page sent it, so a test changes only this one value
                "additional_params": {other: v for other, v in values.items() if other != name},
                # a navigation the page made carries the browser's own cookies and no headers of the page's
                "assigned_cookies": sent.get("cookies", {}),
                "assigned_headers": sent.get("headers", {}),
                "host_url": page_url,
                "content_type": request["content_type"],
            }
            await self.emit_event(
                data,
                "WEB_PARAMETER",
                parent=event,
                context=f"{{module}} loaded {page_url} in a browser, whose scripts sent {parameter_type} parameter [{name}]",
            )

    @staticmethod
    def _first_values(query):
        """`query`'s parameters, each with the first value it was sent with."""
        values = {}
        for name, value in parse_qsl(query, keep_blank_values=True):
            values.setdefault(name, value)
        return values
