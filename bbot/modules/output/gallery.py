import os
import json
import time
import secrets
from pathlib import Path
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule
from bbot.core.config.models import BaseModuleConfig, Field

# perceptual hash distances the page can group at, from identical to loosely similar
GROUP_LEVELS = [0, 4, 8, 12]
THUMBNAIL_WIDTH = 480
# response headers kept per screenshot
MAX_HEADER_BYTES = 16 * 1024
SCHEMA_VERSION = 1


class gallery(BaseOutputModule):
    """
    A static, offline HTML gallery of the scan's screenshots, grouped by how alike they look, with what the scan
    learned about each page and host. Rewritten during the scan so an open page fills in as it goes.

    Layout, under the gallery folder:
        data/manifest.js    what's changed; the page polls it
        data/shots-NNN.js   screenshots, `chunk_size` per file
        data/meta.js        per-host data that keeps arriving (technologies, findings, WAFs), and the findings
        thumbnails/         one WebP per distinct screenshot
        gallery.json        everything, written when the scan ends (see `_document()` for the format)
    """

    watched_events = ["WEBSCREENSHOT", "HTTP_RESPONSE", "URL_UNVERIFIED", "TECHNOLOGY", "FINDING", "WAF"]
    meta = {
        "description": "Browse the scan's screenshots in an HTML gallery, grouped by how alike they look",
        "created_date": "2026-10-24",
        "author": "@liquidsec",
    }
    deps_pip = ["pillow"]
    # screenshots per data file; a full one never changes again, so an open page loads it once
    chunk_size = 500

    class Config(BaseModuleConfig):
        output_dir: str = Field("", description="Where to write the gallery (default is inside the scan's folder)")
        refresh_interval: int = Field(30, description="How often to rewrite the gallery during the scan, in seconds")

    async def setup(self):
        output_dir = self.config.get("output_dir", "")
        self.gallery_dir = Path(output_dir) if output_dir else self.scan.home / "gallery"
        self.data_dir = self.gallery_dir / "data"
        self.thumbnail_dir = self.gallery_dir / "thumbnails"
        self.helpers.mkdir(self.data_dir)
        self.helpers.mkdir(self.thumbnail_dir)
        self.refresh_interval = self.config.get("refresh_interval", 30)
        # tells an open page a different scan has written here, so it starts over
        self.generation = secrets.token_hex(8)
        self.rev = 0

        self.screenshots = []
        # chunk number -> revision it was last written at; a chunk whose screenshots changed is rewritten
        self.chunk_revs = {}
        self.dirty_chunks = set()
        self.meta_rev = 0
        self.meta_dirty = True

        # per level: [(hash, group)] in the order groups were founded; level 0 is an exact match
        self.leaders = {level: [] for level in GROUP_LEVELS if level}
        self.exact_groups = {}
        self.group_counts = {level: 0 for level in GROUP_LEVELS}

        # an HTML response's details, until the page's screenshot arrives
        self.responses = {}
        self.js_redirects = {}
        self.shots_by_url = {}
        self.hosts = {}
        self.findings = []

        self._flush_task = self.helpers.create_task(self._flush_loop())
        return True

    async def handle_event(self, event):
        handler = getattr(self, f"_handle_{event.type.lower()}")
        await handler(event)

    # -- events --

    async def _handle_webscreenshot(self, event):
        data = event.data
        page = event.parent
        page_url = getattr(page, "url", None) or data["url"]
        record = {
            "id": len(self.screenshots),
            "url": data["url"],
            "requested_url": page_url,
            "host": str(event.host),
            "port": event.port,
            "file": self._link(data["path"]),
            "thumbnail": f"thumbnails/{data['sha256']}.webp",
            "sha256": data["sha256"],
            "size": data["size"],
            "width": data["width"],
            "height": data["height"],
            "dhash": data["dhash"],
            "blank": data.get("blank", False),
            "groups": self._group(data["dhash"], data.get("blank", False)),
            "timestamp": event.timestamp.timestamp(),
            "status": getattr(page, "http_status", 0),
            "title": getattr(page, "http_title", ""),
            "content_type": getattr(page, "content_type", ""),
            "redirect": getattr(page, "redirect_location", ""),
            "js_redirect": self.js_redirects.get(page_url, ""),
            "server": "",
            "headers": [],
            "cert": None,
            "ips": sorted(str(ip) for ip in event.resolved_hosts),
            "scope_distance": event.scope_distance,
            "tags": sorted(set(page.tags) | set(event.tags)) if page is not None else sorted(event.tags),
            "discovery_path": list(event.discovery_path),
        }
        response = self.responses.pop(data["url"], None) or self.responses.pop(page_url, None)
        if response is not None:
            record.update(response)
        self.screenshots.append(record)
        for url in {data["url"], page_url}:
            self.shots_by_url.setdefault(url, []).append(record["id"])

        host = self._host(record["host"])
        host["screenshots"] += 1
        host["ips"].update(record["ips"])
        host["metadata"].update(event.host_metadata or {})
        for rdtype, records in (event.dns_children or {}).items():
            host["dns"].setdefault(rdtype, set()).update(str(r) for r in records)

        self.dirty_chunks.add(record["id"] // self.chunk_size)
        self.meta_dirty = True
        await self.helpers.run_in_executor_cpu(self._make_thumbnail, data["path"], data["sha256"])

    async def _handle_http_response(self, event):
        # the rendered DOM's response carries the same headers; the page itself is all that's needed
        if "browser-dom" in event.tags or "in-scope" not in event.tags:
            return
        data = event.data
        content_type = data.get("content_type", "").split(";")[0].strip().lower()
        # only pages get screenshotted, and never redirects; anything else would wait here for nothing
        if content_type not in ("", "text/html", "application/xhtml+xml") or 300 <= data.get("status_code", 0) < 400:
            return
        details = {
            "status": data.get("status_code", 0),
            "title": data.get("title", ""),
            "server": data.get("header", {}).get("server", ""),
            "headers": self._headers(data.get("raw_header", "")),
            "cert": self._cert(data.get("cert_info")),
        }
        url = data["url"]
        shots = self.shots_by_url.get(url)
        if shots is None:
            self.responses[url] = details
            return
        # the screenshot got here first
        for shot_id in shots:
            self.screenshots[shot_id].update(details)
            self.dirty_chunks.add(shot_id // self.chunk_size)

    async def _handle_url_unverified(self, event):
        if "js-redirect" not in event.tags:
            return
        page_url = getattr(event.parent, "url", None)
        if not page_url:
            return
        self.js_redirects[page_url] = event.url
        for shot_id in self.shots_by_url.get(page_url, []):
            self.screenshots[shot_id]["js_redirect"] = event.url
            self.dirty_chunks.add(shot_id // self.chunk_size)

    async def _handle_technology(self, event):
        technology = event.data.get("technology", "")
        if technology:
            self._host(event.data.get("host", str(event.host)))["technologies"].add(technology)
            self.meta_dirty = True

    async def _handle_finding(self, event):
        data = event.data
        finding = {
            "id": len(self.findings),
            "host": data.get("host", str(event.host)),
            "url": data.get("url", ""),
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "severity": data.get("severity", ""),
            "confidence": data.get("confidence", ""),
        }
        self.findings.append(finding)
        self._host(finding["host"])["findings"].append(finding["id"])
        self.meta_dirty = True

    async def _handle_waf(self, event):
        waf = event.data.get("waf", "")
        if waf:
            self._host(event.data.get("host", str(event.host)))["wafs"].add(waf)
            self.meta_dirty = True

    # -- grouping --

    def _group(self, dhash, blank):
        """This screenshot's group at each level. Blank screenshots don't group: their hashes say nothing."""
        if blank:
            return None
        value = int(dhash, 16)
        groups = []
        for level in GROUP_LEVELS:
            if level == 0:
                group = self.exact_groups.get(value)
                if group is None:
                    group = self.exact_groups[value] = self._new_group(level)
            else:
                # join the first group whose founding screenshot is close enough, so a group never changes once made
                group = next(
                    (g for leader, g in self.leaders[level] if (leader ^ value).bit_count() <= level),
                    None,
                )
                if group is None:
                    group = self._new_group(level)
                    self.leaders[level].append((value, group))
            groups.append(group)
        return groups

    def _new_group(self, level):
        self.group_counts[level] += 1
        return self.group_counts[level] - 1

    # -- writing --

    async def _flush_loop(self):
        while True:
            await self.helpers.sleep(self.refresh_interval)
            with suppress(Exception):
                self._flush()

    def _flush(self, force=False):
        if not (self.dirty_chunks or self.meta_dirty or force):
            return
        self.rev += 1
        for chunk in sorted(self.dirty_chunks):
            shots = self.screenshots[chunk * self.chunk_size : (chunk + 1) * self.chunk_size]
            self._write_js(self._chunk_file(chunk), "shots", {"chunk": chunk, "screenshots": shots})
            self.chunk_revs[chunk] = self.rev
        self.dirty_chunks.clear()
        if self.meta_dirty:
            self._write_js("meta.js", "meta", self._meta())
            self.meta_rev = self.rev
            self.meta_dirty = False
        self._write_js("manifest.js", "manifest", self._manifest())
        self.debug(f"Updated the gallery at {self.gallery_dir} ({len(self.screenshots):,} screenshots)")

    def _manifest(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "generation": self.generation,
            "rev": self.rev,
            "updated": time.time(),
            "scan": {
                "name": self.scan.name,
                "id": self.scan.id,
                "status": self.scan.status,
                "started": self.scan.start_time.timestamp() if self.scan.start_time else None,
            },
            "levels": GROUP_LEVELS,
            "total": len(self.screenshots),
            "chunks": [
                {
                    "file": self._chunk_file(chunk),
                    "rev": rev,
                    "count": min(self.chunk_size, len(self.screenshots) - chunk * self.chunk_size),
                }
                for chunk, rev in sorted(self.chunk_revs.items())
            ],
            "meta": {"file": "meta.js", "rev": self.meta_rev},
        }

    def _meta(self):
        hosts = {name: host for name, host in self.hosts.items() if host["screenshots"]}
        # other hosts in the gallery on the same IPs: virtual hosts sharing a server
        by_ip = {}
        for name, host in hosts.items():
            for ip in host["ips"]:
                by_ip.setdefault(ip, set()).add(name)
        finding_ids = set()
        out = {}
        for name, host in hosts.items():
            finding_ids.update(host["findings"])
            out[name] = {
                "ips": sorted(host["ips"]),
                "shared_ip_hosts": sorted(set().union(*(by_ip[ip] for ip in host["ips"])) - {name})
                if host["ips"]
                else [],
                "metadata": host["metadata"],
                "dns": {rdtype: sorted(records) for rdtype, records in host["dns"].items()},
                "technologies": sorted(host["technologies"]),
                "findings": host["findings"],
                "wafs": sorted(host["wafs"]),
                "browser_only": self.helpers.web.is_browser_only(name),
            }
        return {"hosts": out, "findings": [self.findings[i] for i in sorted(finding_ids)]}

    def _document(self):
        """
        gallery.json:
            schema_version  int
            scan            {name, id, status, started}
            levels          the perceptual hash distances groups were made at, matching each screenshot's `groups`
            screenshots     [{id, url, requested_url, host, port, file, thumbnail, sha256, size, width, height, dhash,
                              blank, groups, timestamp, status, title, content_type, redirect, js_redirect, server,
                              headers, cert, ips, scope_distance, tags, discovery_path}]
                            `groups` is the group id at each level, or null for a blank screenshot. `file` and
                            `thumbnail` are relative to the gallery folder.
            hosts           {host: {ips, shared_ip_hosts, metadata, dns, technologies, findings, wafs, browser_only}}
            findings        [{id, host, url, name, description, severity, confidence}], referenced by hosts' `findings`
        """
        manifest = self._manifest()
        meta = self._meta()
        return {
            "schema_version": SCHEMA_VERSION,
            "scan": manifest["scan"],
            "levels": GROUP_LEVELS,
            "screenshots": self.screenshots,
            "hosts": meta["hosts"],
            "findings": meta["findings"],
        }

    async def report(self):
        if self._flush_task is not None:
            self._flush_task.cancel()
            self._flush_task = None
        # the scan's status changed even if nothing else did
        self.meta_dirty = True
        self._flush(force=True)
        await self.helpers.run_in_executor_io(self._write_json, "gallery.json", self._document())

    async def cleanup(self):
        if self._flush_task is not None:
            self._flush_task.cancel()

    def _write_js(self, filename, callback, data):
        # loaded with a script tag, which works from file:// where fetching a JSON file doesn't
        self._write(self.data_dir / filename, f"bbotGallery.{callback}({json.dumps(data)});\n")

    def _write_json(self, filename, data):
        self._write(self.gallery_dir / filename, json.dumps(data))

    @staticmethod
    def _write(path, text):
        # written whole and then swapped in, so an open page never reads half a file
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_text(text)
        os.replace(tmp, path)

    @staticmethod
    def _chunk_file(chunk):
        return f"shots-{chunk:04d}.js"

    # -- helpers --

    def _host(self, name):
        host = self.hosts.get(name)
        if host is None:
            host = self.hosts[name] = {
                "screenshots": 0,
                "ips": set(),
                "metadata": {},
                "dns": {},
                "technologies": set(),
                "findings": [],
                "wafs": set(),
            }
        return host

    def _screenshot_path(self, path):
        path = Path(path)
        return path if path.is_absolute() else self.scan.home / path

    def _link(self, path):
        """The screenshot's location as the page refers to it: relative if it can be, otherwise a file:// URL."""
        full = self._screenshot_path(path)
        try:
            return os.path.relpath(full, self.gallery_dir)
        except ValueError:
            return full.as_uri()

    def _make_thumbnail(self, path, sha256):
        thumbnail = self.thumbnail_dir / f"{sha256}.webp"
        if thumbnail.exists():
            return
        from PIL import Image

        with Image.open(self._screenshot_path(path)) as image:
            height = round(image.height * THUMBNAIL_WIDTH / image.width)
            image.convert("RGB").resize((THUMBNAIL_WIDTH, height), Image.Resampling.LANCZOS).save(
                thumbnail, "WEBP", quality=80
            )

    @staticmethod
    def _headers(raw_header):
        headers = []
        size = 0
        # the first line is the status line
        for line in raw_header.split("\r\n")[1:]:
            name, sep, value = line.partition(":")
            if not sep:
                continue
            size += len(line)
            if size > MAX_HEADER_BYTES:
                break
            headers.append([name.strip(), value.strip()])
        return headers

    @staticmethod
    def _cert(cert_info):
        cert = {
            k: (cert_info or {}).get(k)
            for k in ("common_name", "sans", "issuer", "not_before", "not_after", "fingerprint_sha256")
        }
        return cert if any(cert.values()) else None
