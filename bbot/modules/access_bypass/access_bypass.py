import importlib

from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import get_waf_strings
from bbot.core.config.models import BaseModuleConfig, Field

SUBMODULES = ["path", "headers", "auth", "extension_routing", "nextjs"]


class access_bypass(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "loud", "web-heavy"]
    meta = {
        "description": "Probe URLs for access-control, routing, and auth bypasses (403/401/406 bypasses, "
        "path and header manipulation, API Gateway and Next.js data-route bypasses)",
        "created_date": "2026-10-22",
        "author": "@liquidsec",
    }
    in_scope_only = True

    class Config(BaseModuleConfig):
        enabled_submodules: list[str] = Field(
            ["path", "headers", "auth", "extension_routing", "nextjs"],
            description="Which access_bypass submodules to run. Empty list enables all.",
        )
        allow_redirects: bool = Field(
            True,
            description="Follow redirects when comparing responses. Disabling trades false positives for false negatives.",
        )

    # when more than this many signatures fire on one URL, collapse into a single finding
    collapse_threshold = 6

    async def setup(self):
        self.allow_redirects = self.config.get("allow_redirects", True)
        # one stable canary per scan, shared by the extension-routing probes
        self.rand_string = self.helpers.rand_string()
        self.waf_yara_rules = self.helpers.yara.compile_strings(get_waf_strings(), nocase=True)
        # scratch space shared across events (e.g. nextjs buildId cache)
        self.submodule_state = {}

        enabled = self.config.get("enabled_submodules") or SUBMODULES
        self.submodules = {}
        for name in enabled:
            try:
                module = importlib.import_module(f"bbot.modules.access_bypass.submodules.{name}")
                self.submodules[name] = getattr(module, name)
            except (ImportError, AttributeError):
                return False, f"Invalid access_bypass submodule specified: {name}"
        return True

    async def is_waf_response(self, response):
        if response is None or response.text is None:
            return False
        return bool(await self.helpers.yara.match(self.waf_yara_rules, response.text))

    def _applicable_submodules(self, event, compare_helper):
        for submodule_class in self.submodules.values():
            instance = submodule_class(self, event, compare_helper)
            if instance.applies():
                yield instance

    async def filter_event(self, event):
        # applies() only reads event status/redirect, so a null compare_helper is fine here
        if any(cls(self, event, None).applies() for cls in self.submodules.values()):
            return True
        return False, "no access_bypass submodule applies to this URL"

    async def handle_event(self, event):
        # blocked-mode checks must not follow redirects (a 302 to /login is not a bypass);
        # the 2xx extension-routing mode keeps the configured behavior
        follow_redirects = self.allow_redirects if event.http_status not in (401, 403, 406, 429) else False
        try:
            compare_helper = self.helpers.http_compare(
                event.url, allow_redirects=follow_redirects, include_cache_buster=False
            )
        except HttpCompareError as e:
            self.debug(e)
            return

        results = []
        for submodule in self._applicable_submodules(event, compare_helper):
            try:
                await submodule.run()
            except HttpCompareError as e:
                self.debug(f"{submodule.friendly_name} aborted for {event.url}: {e}")
            results.extend(submodule.results)

        if not results:
            return

        # A host that trips many signatures at once is an unstable baseline or a catch-all,
        # not a stack of real bypasses. Suppress rather than emit a low-signal finding.
        if len(results) > self.collapse_threshold:
            self.verbose(
                f"Suppressing {len(results)} access_bypass signatures for {event.url}: "
                f"too many to be real (likely catch-all or unstable baseline)"
            )
            return

        for result in results:
            await self.emit_event(
                {
                    "name": result["name"],
                    "description": result["description"],
                    "host": str(event.host),
                    "url": result["url"],
                    "severity": result["severity"],
                    "confidence": result["confidence"],
                },
                "FINDING",
                parent=event,
                context=f"{{module}} probed {event.url} and identified {{event.type}}: {result['description']}",
            )
