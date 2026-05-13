from urllib.parse import urlparse

from bbot.errors import ValidationError
from bbot.modules.base import BaseModule


class sslcert(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS"]
    flags = ["safe", "affiliates", "subdomain-enum", "email-enum", "active", "web"]
    meta = {
        "description": "Extract hostnames and emails from TLS certificates in HTTP responses",
        "created_date": "2022-03-30",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = 1
    _priority = 2

    async def setup(self):
        # sometimes we run into a server with A LOT of SANs
        # these are usually stupid and useless, so we abort based on a different threshold
        # depending on whether the parent event is in scope
        self.in_scope_abort_threshold = 50
        self.out_of_scope_abort_threshold = 10
        self.hosts_visited = set()
        return True

    async def handle_event(self, event):
        # Only process HTTPS responses with certificate info
        cert_info = event.data.get("cert_info")
        if not cert_info:
            return

        # Deduplicate by (host, port) to avoid processing the same cert twice
        url = event.data.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        host_hash = hash((host, port))
        if host_hash in self.hosts_visited:
            return
        self.hosts_visited.add(host_hash)

        # Extract DNS names and emails from cert_info
        common_name = (cert_info.get("common_name") or "").lstrip("*.").lower()
        sans = [s.lstrip("*.").lower() for s in cert_info.get("sans", [])]
        emails = set(cert_info.get("emails", []))

        # Build DNS names list: CN first, then SANs (excluding CN)
        dns_names = []
        if common_name:
            dns_names.append(common_name)
        for san in sans:
            if san and san not in dns_names:
                dns_names.append(san)

        # Apply threshold
        if event.scope_distance == 0:
            abort_threshold = self.in_scope_abort_threshold
        else:
            abort_threshold = self.out_of_scope_abort_threshold

        if len(dns_names) > abort_threshold:
            self.verbose(
                f"Skipping SANs on {url} because count ({len(dns_names):,}) exceeds threshold ({abort_threshold})"
            )
            dns_names = dns_names[:1] + [n for n in dns_names[1:] if self.scan.in_scope(n)]

        # Emit events
        for event_type, results in (("DNS_NAME", set(dns_names)), ("EMAIL_ADDRESS", emails)):
            for event_data in results:
                if event_data is not None and event_data != str(event.host):
                    self.debug(f"Discovered new {event_type} via TLS certificate: [{event_data}]")
                    try:
                        ssl_event = self.make_event(event_data, event_type, parent=event, raise_error=True)
                        parent_event = ssl_event.get_parent()
                        if parent_event.scope_distance == 0:
                            tags = ["affiliate"]
                        else:
                            tags = None
                        if ssl_event:
                            await self.emit_event(
                                ssl_event,
                                tags=tags,
                                context=f"{{module}} parsed TLS certificate at {url} and found {{event.type}}: {{event.data}}",
                            )
                    except ValidationError as e:
                        self.hugeinfo(f'Malformed {event_type} "{event_data}" at {url}')
                        self.debug(f"Invalid data at {url}: {e}")

    def on_success_callback(self, event):
        parent_scope_distance = event.get_parent().scope_distance
        if parent_scope_distance == 0 and event.scope_distance > 0:
            event.add_tag("affiliate")
