import asyncio
from OpenSSL import crypto
from contextlib import suppress

from bbot.errors import ValidationError
from bbot.modules.base import BaseModule
from bbot.core.helpers.async_helpers import NamedLock
from bbot.core.helpers.web.ssl_context import ssl_context_noverify


class sslcert(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS"]
    flags = ["affiliates", "subdomain-enum", "email-enum", "active", "safe", "web-basic"]
    meta = {
        "description": "Visit open ports and retrieve SSL certificates",
        "created_date": "2022-03-30",
        "author": "@TheTechromancer",
    }
    options = {"timeout": 5.0, "skip_non_ssl": True}
    options_desc = {"timeout": "Socket connect timeout in seconds", "skip_non_ssl": "Don't try common non-SSL ports"}
    deps_apt = ["openssl"]
    deps_pip = ["pyOpenSSL~=24.0.0"]
    _module_threads = 25
    scope_distance_modifier = 1
    _priority = 2

    async def setup(self):
        self.timeout = self.config.get("timeout", 5.0)
        self.skip_non_ssl = self.config.get("skip_non_ssl", True)
        self.non_ssl_ports = (22, 53, 80)

        # sometimes we run into a server with A LOT of SANs
        # these are usually stupid and useless, so we abort based on a different threshold
        # depending on whether the parent event is in scope
        self.in_scope_abort_threshold = 50
        self.out_of_scope_abort_threshold = 10

        self.hosts_visited = set()
        self.ip_lock = NamedLock()
        return True

    async def filter_event(self, event):
        if self.skip_non_ssl and event.port in self.non_ssl_ports:
            return False, f"Port {event.port} doesn't typically use SSL"
        return True

    async def handle_event(self, event):
        _host = event.host
        if event.port:
            port = event.port
        else:
            port = 443

        # turn hostnames into IP address(es)
        if self.helpers.is_ip(_host):
            hosts = [_host]
        else:
            hosts = list(await self.helpers.resolve(_host))

        if event.scope_distance == 0:
            abort_threshold = self.in_scope_abort_threshold
        else:
            abort_threshold = self.out_of_scope_abort_threshold

        tasks = [self.visit_host(host, port) for host in hosts]
        async for task in self.helpers.as_completed(tasks):
            result = await task
            if not isinstance(result, tuple) or not len(result) == 3:
                continue
            dns_names, emails, (host, port) = result
            if len(dns_names) > abort_threshold:
                netloc = self.helpers.make_netloc(host, port)
                self.verbose(
                    f"Skipping Subject Alternate Names (SANs) on {netloc} because number of hostnames ({len(dns_names):,}) exceeds threshold ({abort_threshold})"
                )
                dns_names = dns_names[:1] + [n for n in dns_names[1:] if self.scan.in_scope(n)]
            for event_type, results in (("DNS_NAME", set(dns_names)), ("EMAIL_ADDRESS", emails)):
                for event_data in results:
                    if event_data is not None and event_data != event:
                        self.debug(f"Discovered new {event_type} via SSL certificate parsing: [{event_data}]")
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
                                    context=f"{{module}} parsed SSL certificate at {event.data} and found {{event.type}}: {{event.data}}",
                                )
                        except ValidationError as e:
                            self.hugeinfo(f'Malformed {event_type} "{event_data}" at {event.data}')
                            self.debug(f"Invalid data at {host}:{port}: {e}")

    def on_success_callback(self, event):
        parent_scope_distance = event.get_parent().scope_distance
        if parent_scope_distance == 0 and event.scope_distance > 0:
            event.add_tag("affiliate")

    async def visit_host(self, host, port):
        host = self.helpers.make_ip_type(host)
        netloc = self.helpers.make_netloc(host, port)
        host_hash = hash((host, port))
        dns_names = []
        emails = set()
        async with self.ip_lock.lock(host_hash):
            if host_hash in self.hosts_visited:
                self.debug(f"Already processed {host} on port {port}, skipping")
                return [], [], (host, port)
            else:
                self.hosts_visited.add(host_hash)

            host = str(host)

            # Connect to the host
            try:
                transport, _ = await asyncio.wait_for(
                    self.helpers.loop.create_connection(
                        lambda: asyncio.Protocol(), host, port, ssl=ssl_context_noverify
                    ),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                self.debug(f"Timed out after {self.timeout} seconds while connecting to {netloc}")
                return [], [], (host, port)
            except Exception as e:
                log_fn = self.warning
                if isinstance(e, OSError):
                    log_fn = self.debug
                log_fn(f"Error connecting to {netloc}: {e}")
                return [], [], (host, port)
            finally:
                with suppress(Exception):
                    transport.close()

            # Get the SSL object
            try:
                ssl_object = transport.get_extra_info("ssl_object")
            except Exception as e:
                self.verbose(f"Error getting ssl_object: {e}", trace=True)
                return [], [], (host, port)

            # Get the certificate
            try:
                der = ssl_object.getpeercert(binary_form=True)
            except Exception as e:
                self.verbose(f"Error getting peer cert: {e}", trace=True)
                return [], [], (host, port)
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
            except Exception as e:
                self.verbose(f"Error loading certificate: {e}", trace=True)
                return [], [], (host, port)
            issuer = cert.get_issuer()
            if issuer.emailAddress and self.helpers.regexes.email_regex.match(issuer.emailAddress):
                emails.add(issuer.emailAddress)
            subject = cert.get_subject()
            if subject.emailAddress and self.helpers.regexes.email_regex.match(subject.emailAddress):
                emails.add(subject.emailAddress)
            common_name = str(subject.commonName).lstrip("*.").lower()
            dns_names = set(self.get_cert_sans(cert))
            with suppress(KeyError):
                dns_names.remove(common_name)
            dns_names = [common_name] + list(dns_names)
        return dns_names, list(emails), (host, port)

    @staticmethod
    def get_cert_sans(cert):
        sans = []
        raw_sans = None
        ext_count = cert.get_extension_count()
        for i in range(0, ext_count):
            ext = cert.get_extension(i)
            short_name = str(ext.get_short_name())
            if "subjectAltName" in short_name:
                raw_sans = str(ext)
        if raw_sans is not None:
            for raw_san in raw_sans.split(","):
                hostname = raw_san.split(":", 1)[-1].strip().lower()
                # IPv6 addresses
                if hostname.startswith("[") and hostname.endswith("]"):
                    hostname = hostname.strip("[]")
                hostname = hostname.lstrip("*.")
                sans.append(hostname)
        return sans
