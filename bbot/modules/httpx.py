import re
import json
import tempfile
import subprocess
from pathlib import Path
from bbot.modules.base import BaseModule
from bbot.core.helpers.web import is_login_page


class httpx(BaseModule):
    watched_events = ["OPEN_TCP_PORT", "URL_UNVERIFIED", "URL"]
    produced_events = ["URL", "HTTP_RESPONSE"]
    flags = ["active", "safe", "web-basic", "web-thorough", "social-enum", "subdomain-enum", "cloud-enum"]
    meta = {
        "description": "Visit webpages. Many other modules rely on httpx",
        "created_date": "2022-07-08",
        "author": "@TheTechromancer",
    }

    options = {
        "threads": 50,
        "in_scope_only": True,
        "version": "1.2.5",
        "max_response_size": 5242880,
        "store_responses": False,
        "probe_all_ips": False,
    }
    options_desc = {
        "threads": "Number of httpx threads to use",
        "in_scope_only": "Only visit web resources that are in scope.",
        "version": "httpx version",
        "max_response_size": "Max response size in bytes",
        "store_responses": "Save raw HTTP responses to scan folder",
        "probe_all_ips": "Probe all the ips associated with same host",
    }
    deps_ansible = [
        {
            "name": "Download httpx",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/httpx/releases/download/v#{BBOT_MODULES_HTTPX_VERSION}/httpx_#{BBOT_MODULES_HTTPX_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.zip",
                "include": "httpx",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    scope_distance_modifier = 1
    _batch_size = 500
    _priority = 2

    async def setup(self):
        self.threads = self.config.get("threads", 50)
        self.timeout = self.scan.config.get("httpx_timeout", 5)
        self.retries = self.scan.config.get("httpx_retries", 1)
        self.max_response_size = self.config.get("max_response_size", 5242880)
        self.store_responses = self.config.get("store_responses", False)
        self.probe_all_ips = self.config.get("probe_all_ips", False)
        self.visited = set()
        self.httpx_tempdir_regex = re.compile(r"^httpx\d+$")
        return True

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"

        if "unresolved" in event.tags:
            return False, "event is unresolved"

        if event.module == self:
            return False, "event is from self"

        if "spider-danger" in event.tags:
            return False, "event has spider danger"

        # scope filtering
        in_scope_only = self.config.get("in_scope_only", True)
        safe_to_visit = "httpx-safe" in event.tags
        if not safe_to_visit and (in_scope_only and not self.scan.in_scope(event)):
            return False, "event is not in scope"

        return True

    async def handle_batch(self, *events):
        stdin = {}
        for e in events:
            url_hash = None
            if e.type.startswith("URL"):
                # we NEED the port, otherwise httpx will try HTTPS even for HTTP URLs
                url = e.with_port().geturl()
                if e.parsed.path == "/":
                    url_hash = hash((e.host, e.port))
            else:
                url = str(e.data)
                url_hash = hash((e.host, e.port))

            if url_hash not in self.visited:
                stdin[url] = e
                if url_hash is not None:
                    self.visited.add(url_hash)

        if not stdin:
            return

        command = [
            "httpx",
            "-silent",
            "-json",
            "-include-response",
            "-threads",
            self.threads,
            "-timeout",
            self.timeout,
            "-retries",
            self.retries,
            "-header",
            f"User-Agent: {self.scan.useragent}",
            "-response-size-to-read",
            f"{self.max_response_size}",
        ]

        if self.store_responses:
            response_dir = self.scan.home / "httpx"
            self.helpers.mkdir(response_dir)
            command += ["-srd", str(response_dir)]

        dns_resolvers = ",".join(self.helpers.system_resolvers)
        if dns_resolvers:
            command += ["-r", dns_resolvers]

        if self.probe_all_ips:
            command += ["-probe-all-ips"]

        for hk, hv in self.scan.config.get("http_headers", {}).items():
            command += ["-header", f"{hk}: {hv}"]
        proxy = self.scan.config.get("http_proxy", "")
        if proxy:
            command += ["-http-proxy", proxy]
        async for line in self.run_process_live(command, input=list(stdin), stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue

            url = j.get("url", "")
            status_code = int(j.get("status_code", 0))
            if status_code == 0:
                self.debug(f'No HTTP status code for "{url}"')
                continue

            source_event = stdin.get(j.get("input", ""), None)

            if source_event is None:
                self.warning(f"Unable to correlate source event from: {line}")
                continue

            # discard 404s from unverified URLs
            path = j.get("path", "/")
            if source_event.type == "URL_UNVERIFIED" and status_code in (404,) and path != "/":
                self.debug(f'Discarding 404 from "{url}"')
                continue

            # main URL
            tags = [f"status-{status_code}"]
            httpx_ip = j.get("host", "")
            if httpx_ip:
                tags.append(f"ip-{httpx_ip}")
            # detect login pages
            if is_login_page(j.get("body", "")):
                tags.append("login-page")
            # grab title
            title = self.helpers.tagify(j.get("title", ""), maxlen=30)
            if title:
                tags.append(f"http-title-{title}")
            url_event = self.make_event(url, "URL", source_event, tags=tags)
            if url_event:
                if url_event != source_event:
                    await self.emit_event(url_event)
                else:
                    url_event._resolved.set()
                # HTTP response
                await self.emit_event(j, "HTTP_RESPONSE", url_event, tags=url_event.tags)

        for tempdir in Path(tempfile.gettempdir()).iterdir():
            if tempdir.is_dir() and self.httpx_tempdir_regex.match(tempdir.name):
                self.helpers.rm_rf(tempdir)

    async def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)
