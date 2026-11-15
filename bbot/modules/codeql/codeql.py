import csv
import os
import re
import tempfile
from pathlib import Path
from typing import Literal

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.templates.browser_vulns import browser_vulns

QUERIES_DIR = Path(__file__).parent / "queries"
# the longest one CodeQL step (building a page's database, or querying it) may take
CODEQL_TIMEOUT = 600
# CodeQL's severities, lowest first, and the FINDING severity each one becomes
SEVERITIES = {"note": "INFO", "recommendation": "LOW", "warning": "MEDIUM", "error": "HIGH"}
# a code location in a CodeQL message: [["label"|"relative:///page.html:3:15:3:27"]]
MESSAGE_LOCATION = re.compile(r'\[\["([^"]*)"\|"relative:///([^:"]+):(\d+):(\d+):\d+:(\d+)"\]\]')
# the page's DOM, in the source root CodeQL builds its database from
PAGE_FILE = "page.html"
# longest code snippet shown in a finding
SNIPPET_MAX = 150


class codeql(browser_vulns):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "slow"]
    meta = {
        "description": "Find client-side web vulnerabilities (DOM XSS, prototype pollution, and more) by analyzing pages' JavaScript with CodeQL",
        "created_date": "2025-03-05",
        "author": "@liquidsec",
    }
    # the page as it stands after its scripts ran, and the scripts it loaded
    browser_artifacts = ["dom", "network"]
    # the bundle ships the CLI with the JavaScript library at the version built for it
    deps_apt = ["zstd"]
    deps_ansible = [
        {
            # so an earlier version's library can't linger beside this one's
            "name": "Remove any earlier CodeQL",
            "file": {"path": "#{BBOT_TOOLS}/codeql", "state": "absent"},
        },
        {
            "name": "Download CodeQL",
            "unarchive": {
                "src": "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-javascript-linux64.tar.zst",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]
    _module_threads = 2

    class Config(BaseModuleConfig):
        mode: Literal["in_scope", "all", "dom_only"] = Field(
            "in_scope",
            description="What to analyze: the page and the scripts it loads from in-scope hosts ('in_scope'), the page and every script it loads ('all'), or only the page ('dom_only')",
        )
        min_severity: Literal["error", "warning", "recommendation", "note"] = Field(
            "error", description="The lowest CodeQL severity to report"
        )
        suppress_duplicates: bool = Field(
            True, description="Report each finding once, rather than on every page with the same code"
        )
        # scripts nearly every site loads from someone else: large, slow to analyze, and never the target's own code
        skip_hosts: list[str] = Field(
            [
                # tag managers and analytics
                "googletagmanager.com",
                "google-analytics.com",
                "googleoptimize.com",
                "segment.com",
                "segment.io",
                "mixpanel.com",
                "amplitude.com",
                "hotjar.com",
                "clarity.ms",
                "newrelic.com",
                "nr-data.net",
                "cloudflareinsights.com",
                "mc.yandex.ru",
                "assets.adobedtm.com",
                # ads and their pixels
                "googlesyndication.com",
                "googleadservices.com",
                "doubleclick.net",
                "amazon-adsystem.com",
                "criteo.com",
                "criteo.net",
                "taboola.com",
                "outbrain.com",
                "ads-twitter.com",
                "bat.bing.com",
                "connect.facebook.net",
                "snap.licdn.com",
                "analytics.tiktok.com",
                # social widgets
                "platform.twitter.com",
                "s.pinimg.com",
                # consent, chat and captcha widgets
                "cookielaw.org",
                "onetrust.com",
                "cookiebot.com",
                "intercom.io",
                "intercomcdn.com",
                "hs-scripts.com",
                "hs-analytics.net",
                "zdassets.com",
                "recaptcha.net",
                "gstatic.com",
                "hcaptcha.com",
            ],
            description="Out-of-scope hosts (and their subdomains) whose scripts aren't analyzed in 'all' mode: tag managers, analytics, ads and widgets, which are slow to analyze and never the target's own code",
        )

    async def setup(self):
        await super().setup()
        self.mode = self.config.get("mode", "in_scope")
        self.min_severity = list(SEVERITIES).index(self.config.get("min_severity", "error"))
        self.suppress_duplicates = self.config.get("suppress_duplicates", True)
        self.skip_hosts = set(self.config.get("skip_hosts") or [])
        self.codeql_bin = self.helpers.tools_dir / "codeql" / "codeql"
        # where CodeQL keeps its compiled queries
        self.codeql_cache = self.helpers.cache_dir / "codeql"
        self.queries = sorted(str(q) for q in QUERIES_DIR.glob("*.ql"))
        self.reported = set()
        # compiled once, so pages don't each wait on it, and a broken install fails here
        result = await self.codeql("query", "compile", *self.queries)
        if result.returncode != 0:
            return False, f"Couldn't compile the CodeQL queries: {result.stderr.strip()[-500:]}"
        return True

    async def handle_event(self, event):
        url = event.url
        page = await self.page_code(event)
        if page is None:
            return
        visit, scripts, fingerprint = page
        findings, first = await self.analyze_once(fingerprint, lambda: self.analyze_page(visit.dom, scripts))
        if not first:
            self.debug(f"Already analyzed a page with the same code as {url}")

        for finding in findings:
            if self.suppress_duplicates:
                if finding in self.reported:
                    continue
                self.reported.add(finding)
            name, severity, source, sink, message = finding
            await self.emit_finding(
                event,
                url=url,
                name=name,
                description=self.describe(url, source, sink, message),
                severity=SEVERITIES[severity],
                confidence="MEDIUM",
                context=f"{{module}} analyzed {url} with CodeQL and found {{event.type}}: {name}",
            )

    def page_scripts(self, visit):
        """The scripts the page loaded that `mode` includes, as {url: code}."""
        if self.mode == "dom_only":
            return {}
        scripts = super().page_scripts(visit)
        if self.mode == "in_scope":
            return {url: script for url, script in scripts.items() if self.scan.in_scope(url)}
        return {url: script for url, script in scripts.items() if self.scan.in_scope(url) or not self.skipped(url)}

    def skipped(self, url):
        """Whether `url` is on one of `skip_hosts`, or a subdomain of one."""
        host = self.helpers.urlparse(url).hostname or ""
        return any(parent in self.skip_hosts for parent in self.helpers.domain_parents(host, include_self=True))

    async def analyze_page(self, dom, scripts):
        """CodeQL's findings for a page, each as (name, severity, source, sink, message)."""
        with tempfile.TemporaryDirectory(dir=self.scan.temp_dir) as temp_dir:
            source_root = Path(temp_dir) / "src"
            source_root.mkdir()
            # where each file came from; None for the page itself
            origins = {PAGE_FILE: None}
            (source_root / PAGE_FILE).write_text(dom)
            for i, (script_url, script) in enumerate(scripts.items()):
                file_name = f"script_{i}.js"
                (source_root / file_name).write_text(script)
                origins[file_name] = script_url
            database = Path(temp_dir) / "db"
            if not await self.create_database(source_root, database):
                return []
            findings = []
            for result in await self.run_queries(database):
                if list(SEVERITIES).index(result["severity"]) >= self.min_severity:
                    findings.append(self.to_finding(result, source_root, origins))
            return list(dict.fromkeys(findings))

    async def create_database(self, source_root, database):
        """Build a CodeQL database from the code in `source_root`. Returns whether it worked."""
        result = await self.codeql(
            "database",
            "create",
            database,
            "--language=javascript",
            f"--source-root={source_root}",
            # the extractor otherwise skips any file that looks minified, which is most of what sites serve
            env=dict(os.environ, CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES="true"),
        )
        if result.returncode == 0:
            return True
        # empty pages leave CodeQL nothing to extract
        if "did not detect any code" in result.stderr or "could not process any of it" in result.stderr:
            self.debug("CodeQL found no code to analyze")
        else:
            self.warning(f"CodeQL couldn't build a database (exit {result.returncode}): {result.stderr[-500:]}")
        return False

    async def run_queries(self, database, queries=None):
        """Run queries on a database (all of them by default), and return their results as dicts."""
        output = Path(database).parent / "results.csv"
        result = await self.codeql(
            "database",
            "analyze",
            database,
            *(queries or self.queries),
            "--format=csv",
            f"--output={output}",
        )
        if result.returncode != 0:
            self.warning(f"CodeQL couldn't query the database (exit {result.returncode}): {result.stderr[-500:]}")
            return []
        fields = ("name", "description", "severity", "message", "file", "line", "column", "end_line", "end_column")
        with open(output, newline="") as f:
            return [dict(zip(fields, row)) for row in csv.reader(f) if len(row) == len(fields)]

    async def codeql(self, *args, **kwargs):
        command = [self.codeql_bin, *args, f"--common-caches={self.codeql_cache}"]
        return await self.run_process(command, idle_timeout=CODEQL_TIMEOUT, _log_stderr=False, **kwargs)

    def to_finding(self, result, source_root, origins):
        sink_file = result["file"].lstrip("/")
        sink_origin = origins.get(sink_file)
        sink = (
            self.snippet(
                source_root / sink_file, int(result["line"]), int(result["column"]), int(result["end_column"])
            ),
            sink_origin,
            # a line in the page's DOM means nothing to anyone reading the finding
            int(result["line"]) if sink_origin else None,
        )
        source = None
        # a sink reached from several sources is one result, its message a line for each; the first is reported
        first_message = result["message"].splitlines()[0] if result["message"] else ""
        location = MESSAGE_LOCATION.search(first_message)
        if location:
            _, file_name, line, column, end_column = location.groups()
            source = (
                self.snippet(source_root / file_name, int(line), int(column), int(end_column)),
                origins.get(file_name),
            )
        # each code reference becomes its label: [["the page's URL"|"relative:///..."]] reads "the page's URL"
        message = MESSAGE_LOCATION.sub(lambda m: m.group(1), first_message).strip() or result["description"]
        return (result["name"], result["severity"], source, sink, message)

    def describe(self, page_url, source, sink, message):
        """`<message> Source: [...] | Sink: [...] (Line N) in <script>`, where the sink always names where it is."""
        parts = []
        sink_snippet, sink_origin, sink_line = sink
        if source and source[0]:
            source_snippet, source_origin = source
            label = f"Source: [{source_snippet}]"
            if source_origin != sink_origin:
                label += f" in {source_origin or page_url}"
            parts.append(label)
        # a finding without a source, like a misconfiguration, is just a place in the code
        name = "Sink" if source else "Location"
        label = f"{name}: [{sink_snippet}]" if sink_snippet else f"{name}:"
        if sink_line is not None:
            label += f" (Line {sink_line})"
        parts.append(f"{label} in {sink_origin or page_url}")
        return f"{message} {' | '.join(parts)}"

    @staticmethod
    def snippet(file_path, line, column, end_column):
        """
        The code at a location: its line, or on a long line the code there, widened around anything too short to
        read on its own (a minified `e`). None if the file can't be read.
        """
        try:
            text = Path(file_path).read_text().splitlines()[line - 1]
        except (OSError, IndexError):
            return None
        if len(text.strip()) <= SNIPPET_MAX:
            return text.strip()
        start, end = column - 1, end_column
        context = max(0, (SNIPPET_MAX // 2) - (end - start) // 2)
        if end - start < SNIPPET_MAX:
            start, end = max(0, start - context), end + context
        snippet = text[start:end].strip()
        if len(snippet) > SNIPPET_MAX:
            snippet = snippet[: SNIPPET_MAX - 3] + "..."
        return snippet
