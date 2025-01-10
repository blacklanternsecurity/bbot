import json
from bbot.modules.base import BaseModule


class wpscan(BaseModule):
    watched_events = ["HTTP_RESPONSE", "TECHNOLOGY"]
    produced_events = ["URL_UNVERIFIED", "FINDING", "VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "aggressive"]
    meta = {
        "description": "Wordpress security scanner. Highly recommended to use an API key for better results.",
        "created_date": "2024-05-29",
        "author": "@domwhewell-sage",
    }

    options = {
        "api_key": "",
        "enumerate": "vp,vt,cb,dbe",
        "threads": 5,
        "request_timeout": 5,
        "connection_timeout": 2,
        "disable_tls_checks": True,
        "force": False,
    }
    options_desc = {
        "api_key": "WPScan API Key",
        "enumerate": "Enumeration Process see wpscan help documentation (default: vp,vt,cb,dbe)",
        "threads": "How many wpscan threads to spawn (default is 5)",
        "request_timeout": "The request timeout in seconds (default 5)",
        "connection_timeout": "The connection timeout in seconds (default 2)",
        "disable_tls_checks": "Disables the SSL/TLS certificate verification (Default True)",
        "force": "Do not check if the target is running WordPress or returns a 403",
    }
    deps_apt = ["curl", "make", "gcc"]
    deps_ansible = [
        {
            "name": "Install Ruby Deps (Debian)",
            "package": {"name": ["ruby-rubygems", "ruby-dev"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
        },
        {
            "name": "Install Ruby Deps (Arch)",
            "package": {"name": ["rubygems"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Archlinux'",
        },
        {
            "name": "Install Ruby Deps (Fedora)",
            "package": {"name": ["rubygems", "ruby-devel"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'RedHat'",
        },
        {
            "name": "Install Ruby Deps (Alpine)",
            "package": {"name": ["ruby-dev", "ruby-bundler"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Alpine'",
        },
        {
            "name": "Install wpscan gem",
            "gem": {"name": "wpscan", "state": "latest", "user_install": False},
            "become": True,
        },
    ]

    async def setup(self):
        self.processed = set()
        self.ignore_events = ["xmlrpc", "readme"]
        self.api_key = self.config.get("api_key", "")
        self.enumerate = self.config.get("enumerate", "vp,vt,cb,dbe")
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.threads = self.config.get("threads", 5)
        self.request_timeout = self.config.get("request_timeout", 5)
        self.connection_timeout = self.config.get("connection_timeout", 2)
        self.disable_tls_checks = self.config.get("disable_tls_checks", True)
        self.force = self.config.get("force", False)
        return True

    async def filter_event(self, event):
        host_hash = hash(event.host)
        if host_hash in self.processed:
            return False, "Host has already been processed"
        if event.type == "HTTP_RESPONSE":
            is_redirect = str(event.data["status_code"]).startswith("30")
            if is_redirect:
                return False, "URL is a redirect"
        elif event.type == "TECHNOLOGY":
            if not event.data["technology"].lower().startswith("wordpress"):
                return False, "technology is not wordpress"
        self.processed.add(host_hash)
        return True

    async def handle_event(self, event):
        if event.type == "HTTP_RESPONSE":
            await self.handle_http_response(event)
        elif event.type == "TECHNOLOGY":
            await self.handle_technology(event)

    async def handle_http_response(self, source_event):
        url = source_event.parsed_url._replace(path="/").geturl()
        command = self.construct_command(url)
        output = await self.run_process(command)
        for new_event in self.parse_wpscan_output(output.stdout, url, source_event):
            await self.emit_event(new_event)

    async def handle_technology(self, source_event):
        url = self.get_base_url(source_event)
        command = self.construct_command(url)
        output = await self.run_process(command)
        for new_event in self.parse_wpscan_output(output.stdout, url, source_event):
            await self.emit_event(new_event)

    def construct_command(self, url):
        # base executable
        command = ["wpscan", "--url", url]
        # proxy
        if self.proxy:
            command += ["--proxy", str(self.proxy)]
        # user agent
        command += ["--user-agent", f"'{self.scan.useragent}'"]
        # threads
        command += ["--max-threads", str(self.threads)]
        # request timeout
        command += ["--request-timeout", str(self.request_timeout)]
        # connection timeout
        command += ["--connect-timeout", str(self.connection_timeout)]
        # api key
        if self.api_key:
            command += ["--api-token", f"{self.api_key}"]
        # enumerate
        command += ["--enumerate", self.enumerate]
        # disable tls checks
        if self.disable_tls_checks:
            command += ["--disable-tls-checks"]
        # force
        if self.force:
            command += ["--force"]
        # output format
        command += ["--format", "json"]
        return command

    def parse_wpscan_output(self, output, base_url, source_event):
        json_output = json.loads(output)
        interesting_json = json_output.get("interesting_findings", {}) or {}
        version_json = json_output.get("version", {}) or {}
        theme_json = json_output.get("main_theme", {}) or {}
        plugins_json = json_output.get("plugins", {}) or {}
        if interesting_json:
            yield from self.parse_wp_misc(interesting_json, base_url, source_event)
        if version_json:
            yield from self.parse_wp_version(version_json, base_url, source_event)
        if theme_json:
            yield from self.parse_wp_themes(theme_json, base_url, source_event)
        if plugins_json:
            yield from self.parse_wp_plugins(plugins_json, base_url, source_event)

    def parse_wp_misc(self, interesting_json, base_url, source_event):
        for finding in interesting_json:
            url = finding.get("url", base_url)
            type = finding["type"]
            if type in self.ignore_events:
                continue
            description_string = finding["to_s"]
            interesting_entries = finding["interesting_entries"]
            if type == "headers":
                for header in interesting_entries:
                    yield self.make_event(
                        {"technology": str(header).lower(), "url": url, "host": str(source_event.host)},
                        "TECHNOLOGY",
                        source_event,
                    )
            else:
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=source_event, tags=["httpx-safe"])
                if url_event:
                    yield url_event
                yield self.make_event(
                    {"description": description_string, "url": url, "host": str(source_event.host)},
                    "FINDING",
                    source_event,
                )

    def parse_wp_version(self, version_json, url, source_event):
        version = version_json.get("number", "")
        if version:
            technology = f"wordpress {version}"
        else:
            technology = "wordpress detect"
        yield self.make_event(
            {"technology": str(technology).lower(), "url": url, "host": str(source_event.host)},
            "TECHNOLOGY",
            source_event,
        )
        for wp_vuln in version_json.get("vulnerabilities", []):
            yield self.make_event(
                {
                    "severity": "HIGH",
                    "host": str(source_event.host),
                    "url": url,
                    "description": self.vulnerability_to_s(wp_vuln),
                },
                "VULNERABILITY",
                source_event,
            )

    def parse_wp_themes(self, theme_json, url, source_event):
        name = theme_json.get("slug", "")
        version = theme_json.get("version", {}).get("number", "")
        if name:
            if version:
                technology = f"{name} v{version}"
            else:
                technology = name
        yield self.make_event(
            {"technology": str(technology).lower(), "url": url, "host": str(source_event.host)},
            "TECHNOLOGY",
            source_event,
        )
        for theme_vuln in theme_json.get("vulnerabilities", []):
            yield self.make_event(
                {
                    "severity": "HIGH",
                    "host": str(source_event.host),
                    "url": url,
                    "description": self.vulnerability_to_s(theme_vuln),
                },
                "VULNERABILITY",
                source_event,
            )

    def parse_wp_plugins(self, plugins_json, base_url, source_event):
        for name, plugin in plugins_json.items():
            url = plugin.get("location", base_url)
            if url != base_url:
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=source_event, tags=["httpx-safe"])
                if url_event:
                    yield url_event
            version = plugin.get("version", {}).get("number", "")
            if version:
                technology = f"{name} {version}"
            else:
                technology = name
            yield self.make_event(
                {"technology": str(technology).lower(), "url": url, "host": str(source_event.host)},
                "TECHNOLOGY",
                source_event,
            )
            for vuln in plugin.get("vulnerabilities", []):
                yield self.make_event(
                    {
                        "severity": "HIGH",
                        "host": str(source_event.host),
                        "url": url,
                        "description": self.vulnerability_to_s(vuln),
                    },
                    "VULNERABILITY",
                    source_event,
                )

    def vulnerability_to_s(self, vuln_json):
        string = []
        title = vuln_json.get("title", "")
        string.append(f"Title: {title}")
        fixed_in = vuln_json.get("fixed_in", "")
        string.append(f"Fixed in: {fixed_in}")
        references = vuln_json.get("references", {})
        if references:
            cves = references.get("cve", [])
            urls = references.get("url", [])
            youtube_urls = references.get("youtube", [])
            cves_list = []
            for cve in cves:
                cves_list.append(f"CVE-{cve}")
            if cves_list:
                string.append(f"CVEs: [{', '.join(cves_list)}]")
            if urls:
                string.append(f"References: [{', '.join(urls)}]")
            if youtube_urls:
                string.append(f"Youtube Links: [{', '.join(youtube_urls)}]")
        return " ".join(string)

    def get_base_url(self, event):
        base_url = event.data.get("url", "")
        if not base_url:
            base_url = f"https://{event.host}"
        return self.helpers.urlparse(base_url)._replace(path="/").geturl()
