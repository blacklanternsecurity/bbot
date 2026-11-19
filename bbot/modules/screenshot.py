import hashlib
from io import BytesIO
from pathlib import Path

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field

# a screenshot this much one shade is blank. Near-blank pages measure over 99%; anything with layout, well under 90%
BLANK_THRESHOLD = 0.98


class screenshot(BaseModule):
    watched_events = ["URL", "SOCIAL"]
    produced_events = ["WEBSCREENSHOT", "URL_UNVERIFIED"]
    flags = ["active", "safe", "web-screenshots"]
    meta = {
        "description": "Take screenshots of webpages with a real browser",
        "created_date": "2026-10-23",
        "author": "@liquidsec",
    }
    browser_artifacts = ["screenshot"]
    deps_pip = ["pillow"]
    # SOCIAL pages are accepted up to distance 2; URLs must be in scope (see filter_event)
    scope_distance_modifier = 2
    _module_threads = 4

    class Config(BaseModuleConfig):
        output_path: str = Field("", description="Where to save screenshots (default is inside the scan's folder)")
        social: bool = Field(False, description="Whether to screenshot social media pages")

    async def setup(self):
        self.visit_social = self.config.get("social", False)
        output_path = self.config.get("output_path", "")
        base_path = Path(output_path) if output_path else self.scan.home
        self.screenshot_path = base_path / "screenshots"
        self.helpers.mkdir(self.screenshot_path)
        self.screenshot_count = 0
        return True

    async def filter_event(self, event):
        if any(t.startswith("status-30") for t in event.tags):
            return False, "URL is a redirect"
        if event.type == "SOCIAL":
            if not self.visit_social:
                return False, "social=False"
        # out-of-scope SOCIAL pages are fine, but not URLs
        elif event.scope_distance > 0:
            return False, "event is not in-scope"
        return True

    async def handle_event(self, event):
        url = event.url if event.type == "SOCIAL" else (event.url or event.data)
        visit = await self.browser_visit(event)
        if visit is None or not visit.screenshot:
            return
        if visit.response.conclusion[0] == "needs_browser":
            self.debug(f"Not screenshotting {url}: the browser couldn't get past its challenge")
            return

        png = visit.screenshot
        sha256 = hashlib.sha256(png).hexdigest()
        # stored by content, so identical pages (parked domains, default server pages) are saved once
        path = self.screenshot_path / f"{sha256}.png"
        if not path.exists():
            path.write_bytes(png)
        width, height, dhash, blank = await self.helpers.run_in_executor_cpu(self._image_info, png)
        # relative to the scan's folder when it's inside it, like other file events
        event_path = path.relative_to(self.scan.home) if path.is_relative_to(self.scan.home) else path

        final_url = visit.response.url
        await self.emit_event(
            {
                "url": final_url,
                "path": str(event_path),
                "sha256": sha256,
                "size": len(png),
                "mime_type": "image/png",
                "width": width,
                "height": height,
                "dhash": dhash,
                "blank": blank,
            },
            "WEBSCREENSHOT",
            parent=event,
            context=f"{{module}} visited {final_url} and saved {{event.type}} to {event_path}",
        )
        self.screenshot_count += 1
        self.verbose(f"Screenshot of {final_url}: {path.resolve()}")

    @staticmethod
    def _image_info(png):
        """
        Dimensions; a 64-bit difference hash, in which near-identical pages differ in only a few bits; and whether the
        page is blank. A page that's almost all one shade (an empty error page, one line of text) has no shape for the
        hash to capture, so it hashes like every other near-blank page.
        """
        from PIL import Image

        with Image.open(BytesIO(png)) as image:
            width, height = image.size
            gray = image.convert("L")
        # each bit says whether a pixel is brighter than its right-hand neighbor, on a 9x8 grayscale thumbnail
        pixels = gray.resize((9, 8), Image.Resampling.LANCZOS).tobytes()
        bits = 0
        for row in range(8):
            for col in range(8):
                bits = (bits << 1) | (pixels[row * 9 + col] > pixels[row * 9 + col + 1])
        histogram = gray.resize((160, 90)).histogram()
        blank = max(histogram) / sum(histogram) >= BLANK_THRESHOLD
        return width, height, f"{bits:016x}", blank

    async def report(self):
        if self.screenshot_count:
            self.success(f"{self.screenshot_count:,} web screenshots captured. Saved to: {self.screenshot_path}")
        else:
            self.info("No web screenshots captured")
