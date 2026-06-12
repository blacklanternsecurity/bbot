from .base import BaseModule

from typing import Optional
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig
from domino.DOMino import Domino
from domino.lib.errors import DominoError
from playwright.async_api import async_playwright


class domino(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Check for Client-side Web Vulnerabilities with DOMino",
        "created_date": "2025-04-08",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        rules: Optional[list[str]] = Field(
            default=None,
            description="List of rules to run. None for all rules (default).",
        )
        suppress_parameter_discovery_reports: bool = Field(
            default=True,
            description="Allow parameter discovery to drive rules but suppress reporting the discovery itself",
        )

    module_threads = 3
    deps_pip = ["playwright", "d0m1n0"]

    async def setup(self):
        import asyncio.base_subprocess

        def quiet_transport_del(self):
            try:
                self.close()
            except Exception:
                pass

        asyncio.base_subprocess.BaseSubprocessTransport.__del__ = quiet_transport_del

        # Process rules
        rules = self.config.get("rules")
        if rules is not None:
            self.rules = rules
        else:
            self.rules = None

        self.playwright = await async_playwright().start()

        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        return True

    async def handle_event(self, event):
        url = event.url
        browser_instance = await self.playwright.chromium.launch(headless=True)
        self.debug(f"Domino starting browser instance for {url}")
        try:
            d = Domino(url=url, logger=self.log, json_mode=True, selected_rules=self.rules)
            results = await d.run(self.playwright, browser_instance)
        except DominoError as e:
            self.hugewarning(f"Error running Domino, setting error state: {e}")
            self.errored = True
            return

        if results:
            for result in results:
                if self.suppress_parameter_discovery_reports and "GET Parameter Access" in result["rule_name"]:
                    continue

                details = result.get("details", [])
                details_string = f" Details: [{','.join(details)}]" if details else ""

                interactions = result.get("interactions", [])
                interactions_string = f" Interactions: [{','.join(interactions)}]" if interactions else ""

                severity = result.get("severity", "medium").upper()
                data = {
                    "name": result["rule_name"],
                    "description": f"{result['description']}.{details_string} Detection URL: [{result['detection_url']}]{interactions_string}",
                    "host": str(event.host),
                    "url": result.get("detection_url"),
                    "severity": severity,
                    "confidence": "CONFIRMED",
                }
                await self.emit_event(data, "FINDING", event)
        self.debug(f"Domino browser instance shutting down for {url}")
        await browser_instance.close()
        self.debug(f"DOMino browser shutdown complete for {url}")

    async def cleanup(self):
        await self.playwright.stop()

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            self.debug(f"Rejecting URL {event.data} due to lack of 200 status code. Tags: {event.tags}")
            return False
        return True
