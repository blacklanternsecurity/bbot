from asyncio import wait_for, TimeoutError as AsyncTimeoutError

from .base import BaseModule

from typing import Literal, Optional
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig
from domino.DOMino import Domino
from domino.lib.browser import launch_browser
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
        browser_instances: int = Field(
            default=2,
            description="Number of concurrent browser instances. Each uses ~800-1600 MB of memory under load.",
        )
        engine: Literal["camoufox", "chromium"] = Field(
            default="camoufox",
            description="Browser engine to scan with. Camoufox is a Firefox fork that spoofs fingerprints, making scans harder to identify as automation.",
        )

    _module_threads = 2
    # 0.3.0 is the first release with the engine option (and launch_browser).
    deps_pip = ["playwright", "d0m1n0>=0.3.0"]

    @property
    def module_threads(self):
        return self.config.get("browser_instances", 2)

    async def setup(self):
        import asyncio.base_subprocess  # noqa: E402

        def quiet_transport_del(self):
            try:
                self.close()
            except Exception:
                pass

        asyncio.base_subprocess.BaseSubprocessTransport.__del__ = quiet_transport_del

        self.rules = self.config.get("rules")
        self.engine = self.config.get("engine", "camoufox")

        self._browser_count = self.config.get("browser_instances", 2)
        low_estimate = self._browser_count * 800
        high_estimate = self._browser_count * 1600
        self.warning(
            f"The domino module uses {self.engine.capitalize()}, which consumes a significant amount of memory. "
            f"Your current settings will launch {self._browser_count} instances, for an estimated "
            f"{low_estimate}-{high_estimate} MB. Lower with -c modules.domino.browser_instances=1"
        )

        if self.engine == "camoufox":
            success, message = await self.helpers.run_in_executor_io(self._ensure_camoufox)
            if not success:
                return False, message

        self.playwright = await async_playwright().start()
        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        return True

    def _ensure_camoufox(self):
        """
        Make sure the camoufox browser is on disk before the scan starts.

        camoufox downloads itself on first launch, which would otherwise happen
        inside the first handle_event, with several workers racing for the same
        cache directory. camoufox_path() is that same installer, so this just
        pulls it forward to setup and lets it run once.
        """
        from camoufox.pkgman import camoufox_path, installed_verstr

        try:
            try:
                version = installed_verstr()
            except Exception:
                self.info("Downloading the Camoufox browser (one time, ~100 MB)")
                camoufox_path()
                version = installed_verstr()
            # The browser build is resolved at download time, not pinned by the
            # pip dependency, so two hosts can run different ones. Log it: a
            # detection difference between builds is otherwise invisible.
            self.verbose(f"Camoufox browser build: {version}")
            return True, ""
        except Exception as e:
            return False, (
                f"Failed to install the Camoufox browser ({type(e).__name__}: {e}). "
                f"Install it with 'camoufox fetch', or use -c modules.domino.engine=chromium"
            )

    async def handle_event(self, event):
        url = event.url
        self.debug(f"Domino scanning {url}")
        browser = None
        try:
            browser = await launch_browser(self.playwright, engine=self.engine, headless=True)
            d = Domino(
                url=url,
                logger=self.log,
                json_mode=True,
                selected_rules=self.rules,
                browser_engine=self.engine,
            )
            results = await wait_for(d.run(self.playwright, browser), timeout=120)
        except AsyncTimeoutError:
            self.warning(f"Domino scan timed out after 120s for {url}")
            return
        except DominoError as e:
            self.hugewarning(f"Error running Domino, setting error state: {e}")
            self.errored = True
            return
        except Exception as e:
            self.hugewarning(f"Playwright/Domino fatal error ({type(e).__name__}: {e}), disabling module")
            self.errored = True
            return
        finally:
            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass

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
                    "url": result.get("detection_url") or event.url,
                    "severity": severity,
                    "confidence": "CONFIRMED",
                }
                await self.emit_event(data, "FINDING", event)
        self.debug(f"DOMino scan complete for {url}")

    async def cleanup(self):
        await self.playwright.stop()

    def _incoming_dedup_hash(self, event):
        body_hash = getattr(event, "http_body_hash", "")
        if body_hash:
            return hash((event.host, body_hash)), f"body_hash={body_hash}"
        return hash(event), ""

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            self.debug(f"Rejecting URL {event.data} due to lack of 200 status code. Tags: {event.tags}")
            return False
        return True
