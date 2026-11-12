import re
import base64
import mmh3
import yaml
from urllib.parse import urljoin

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class favicon(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY"]
    flags = ["safe", "active", "web-heavy"]
    meta = {
        "description": "Identify web technologies by the mmh3 hash of their favicon",
        "created_date": "2026-10-16",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        signatures_url: str = Field(
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/favicon-detect.yaml",
            description="URL of the nuclei favicon-detect template to load favicon signatures from",
        )

    _module_threads = 4

    link_tag_regex = re.compile(r"<link\b[^>]*>", re.I)
    link_rel_regex = re.compile(r"""\brel\s*=\s*["']?([^"'>]+)""", re.I)
    link_href_regex = re.compile(r"""\bhref\s*=\s*["']?([^"'\s>]+)""", re.I)
    signature_regex = re.compile(r'"(-?\d+)"\s*==\s*mmh3\(base64_py\(body\)\)')
    # some signature names end in a redundant "favicon" (e.g. "asp.net-favicon")
    name_favicon_suffix_regex = re.compile(r"[-_ ]+(?:default[-_ ]+)?favicon$", re.I)

    async def setup(self):
        signatures_url = self.config.get("signatures_url")
        signatures_file = await self.helpers.download(signatures_url, cache_hrs=24)
        if not signatures_file:
            return None, f"Failed to download favicon signatures from {signatures_url}"
        self.signatures = self.parse_signatures(yaml.safe_load(signatures_file.read_text()))
        if not self.signatures:
            return None, f"No favicon signatures could be parsed from {signatures_url}"
        self.verbose(f"Loaded {len(self.signatures):,} favicon signatures")
        return True

    def parse_signatures(self, template):
        signatures = {}
        for request in template.get("http", []):
            for matcher in request.get("matchers", []):
                name = self.name_favicon_suffix_regex.sub("", matcher.get("name", ""))
                hashes = [int(h) for dsl in matcher.get("dsl", []) for h in self.signature_regex.findall(dsl)]
                if not hashes:
                    self.warning(f"Skipping favicon signature with unrecognized format: {name}")
                    continue
                for h in hashes:
                    signatures.setdefault(h, set()).add(name)
        return signatures

    def icon_urls(self, event):
        """
        Icons declared by the page via <link rel="icon">, followed by the default /favicon.ico.

        If the page declares none and lives in a subdirectory, the subdirectory's favicon.ico is tried
        first, since it may belong to a different app mounted there.
        """
        page_url = event.data["url"]
        urls = []
        for tag in self.link_tag_regex.findall(event.body or ""):
            rel = self.link_rel_regex.search(tag)
            href = self.link_href_regex.search(tag)
            if rel and href and "icon" in rel.group(1).lower().split():
                url = urljoin(page_url, href.group(1))
                if url.startswith(("http://", "https://")):
                    urls.append(url)
        if not urls:
            path_segments = event.parsed_url.path.split("/")
            if len(path_segments) > 2:
                urls.append(urljoin(page_url, f"/{path_segments[1]}/favicon.ico"))
        urls.append(urljoin(page_url, "/favicon.ico"))
        return list(dict.fromkeys(urls))

    def _incoming_dedup_hash(self, event):
        return hash(tuple(self.icon_urls(event))), "already checked these favicons"

    def _outgoing_dedup_hash(self, event):
        # the same favicon across ports, schemes, or subdirectories is the same app
        return hash((event.host, event.data["technology"]))

    async def handle_event(self, event):
        for icon_url in self.icon_urls(event):
            r = await self.helpers.request(icon_url, follow_redirects=True)
            if r is None or r.status_code != 200 or not r.content:
                continue
            if "html" in r.headers.get("content-type", "").lower():
                continue
            favicon_hash = mmh3.hash(base64.encodebytes(r.content))
            names = self.signatures.get(favicon_hash)
            if not names:
                continue
            for technology in sorted(names):
                await self.emit_event(
                    {"host": str(event.host), "url": event.data["url"], "technology": technology},
                    "TECHNOLOGY",
                    parent=event,
                    context=f"{{module}} matched favicon hash {favicon_hash} at {r.url} to {{event.type}}: {technology}",
                )
            return
