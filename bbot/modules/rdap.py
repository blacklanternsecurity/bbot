from typing import Optional

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class rdap(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_REGISTRATION"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Query RDAP for domain registration data, e.g. registrar and registrant organization",
        "created_date": "2026-10-01",
        "author": "@shart123456",
    }

    class Config(BaseModuleConfig):
        follow_registrar: bool = Field(
            True,
            description="Also query the registrar's RDAP server, where most gTLDs keep registrant data",
        )
        include_raw: bool = Field(False, description="Include the raw RDAP JSON responses in the event data")
        timeout: int = Field(10, description="RDAP request timeout in seconds")
        server_concurrency: int = Field(1, description="Maximum concurrent requests per RDAP server")
        server_interval: float = Field(
            1.0, description="Minimum number of seconds between requests to the same RDAP server"
        )
        max_retries: int = Field(
            2, description="How many times to retry a request after being rate-limited (HTTP 429)"
        )
        max_retry_after: Optional[float] = Field(
            None,
            description="Maximum number of seconds to wait when an RDAP server returns HTTP 429 (default: web.429_max_sleep_interval)",
        )
        failure_threshold: int = Field(
            5, description="Stop querying an RDAP server after this many consecutive failures"
        )
        circuit_reset_seconds: float = Field(
            600.0,
            description="How long to skip an RDAP server after it hits failure_threshold, before trying it again",
        )

    # one lookup per registrable domain
    per_domain_only = True
    # registrations of affiliate domains are a shadow IT signal
    scope_distance_modifier = 1
    # rate limits are enforced per RDAP server by the helper (server_concurrency), so lookups against different servers
    # can run in parallel. there are many more threads than per-server slots, so that lookups queued behind a busy
    # server (e.g. verisign for .com) don't occupy every worker while lookups for other servers wait
    _module_threads = 25

    async def setup(self):
        self.follow_registrar = self.config.get("follow_registrar", True)
        self.include_raw = self.config.get("include_raw", False)
        self.helpers.rdap.configure(
            timeout=self.config.get("timeout", 10),
            server_concurrency=self.config.get("server_concurrency", 1),
            server_interval=self.config.get("server_interval", 1.0),
            max_retries=self.config.get("max_retries", 2),
            # None keeps the helper's default (web.429_max_sleep_interval)
            max_retry_after=self.config.get("max_retry_after", None),
            failure_threshold=self.config.get("failure_threshold", 5),
            circuit_reset_seconds=self.config.get("circuit_reset_seconds", 600.0),
        )
        return True

    def registrable_domain(self, hostname):
        """
        Return the registrable domain for a hostname, or None if it doesn't have one
        (e.g. IPs, bare public suffixes, or internal names like "host.local").
        """
        if self.helpers.is_ip(hostname):
            return None
        extracted = self.helpers.tldextract(hostname)
        if not extracted.suffix:
            return None
        return extracted.top_domain_under_public_suffix or None

    async def filter_event(self, event):
        if self.registrable_domain(event.host) is None:
            return False, "No registrable domain"
        return True

    async def handle_event(self, event):
        domain = self.registrable_domain(event.host)
        record = await self.helpers.rdap.lookup(
            domain, follow_registrar=self.follow_registrar, include_raw=self.include_raw
        )
        if not record:
            return
        # the event's host is always the domain we queried, regardless of the case the server returned
        record.pop("domain", None)
        record["host"] = domain
        registration_event = self.make_event(record, "DOMAIN_REGISTRATION", parent=event)
        if registration_event:
            await self.emit_event(
                registration_event,
                context=f'{{module}} queried RDAP ({record["rdap_server"]}) for "{domain}" and found {{event.type}}: {{event.pretty_string}}',
            )
