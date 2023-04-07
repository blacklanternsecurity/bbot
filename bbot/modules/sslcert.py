import select
import socket
import threading
from OpenSSL import SSL
from ssl import PROTOCOL_TLSv1
from contextlib import suppress

from bbot.modules.base import BaseModule
from bbot.core.errors import ValidationError
from bbot.core.helpers.threadpool import NamedLock


class sslcert(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS"]
    flags = ["affiliates", "subdomain-enum", "email-enum", "active", "safe", "web-basic", "web-thorough"]
    meta = {
        "description": "Visit open ports and retrieve SSL certificates",
    }
    options = {"timeout": 5.0, "skip_non_ssl": True}
    options_desc = {"timeout": "Socket connect timeout in seconds", "skip_non_ssl": "Don't try common non-SSL ports"}
    deps_apt = ["openssl"]
    deps_pip = ["pyOpenSSL~=23.1.1"]
    max_threads = 50
    max_event_handlers = 25
    scope_distance_modifier = 1
    _priority = 2

    def setup(self):
        self.timeout = self.config.get("timeout", 5.0)
        self.skip_non_ssl = self.config.get("skip_non_ssl", True)
        self.non_ssl_ports = (22, 53, 80)

        # sometimes we run into a server with A LOT of SANs
        # these are usually stupid and useless, so we abort based on a different threshold
        # depending on whether the source event is in scope
        self.in_scope_abort_threshold = 50
        self.out_of_scope_abort_threshold = 10

        self.hosts_visited = set()
        self.hosts_visited_lock = threading.Lock()
        self.ip_lock = NamedLock()
        return True

    def filter_event(self, event):
        if self.skip_non_ssl and event.port in self.non_ssl_ports:
            return False, f"Port {event.port} doesn't typically use SSL"
        return True

    def handle_event(self, event):
        _host = event.host
        if event.port:
            port = event.port
        else:
            port = 443

        # turn hostnames into IP address(es)
        if self.helpers.is_ip(_host):
            hosts = [_host]
        else:
            hosts = list(self.helpers.resolve(_host))

        futures = {}
        for host in hosts:
            future = self.submit_task(self.visit_host, host, port)
            futures[future] = host

        if event.scope_distance == 0:
            abort_threshold = self.in_scope_abort_threshold
            log_fn = self.info
        else:
            abort_threshold = self.out_of_scope_abort_threshold
            log_fn = self.verbose
        for future in self.helpers.as_completed(futures):
            host = futures[future]
            result = future.result()
            if not isinstance(result, tuple) or not len(result) == 2:
                continue
            dns_names, emails = result
            if len(dns_names) > abort_threshold:
                netloc = self.helpers.make_netloc(host, port)
                log_fn(
                    f"Skipping Subject Alternate Names (SANs) on {netloc} because number of hostnames ({len(dns_names):,}) exceeds threshold ({abort_threshold})"
                )
                dns_names = dns_names[:1]
            for event_type, results in (("DNS_NAME", dns_names), ("EMAIL_ADDRESS", emails)):
                for event_data in results:
                    if event_data is not None and event_data != event:
                        self.debug(f"Discovered new {event_type} via SSL certificate parsing: [{event_data}]")
                        try:
                            ssl_event = self.make_event(event_data, event_type, source=event, raise_error=True)
                            if ssl_event:
                                self.emit_event(ssl_event, on_success_callback=self.on_success_callback)
                        except ValidationError as e:
                            self.hugeinfo(f'Malformed {event_type} "{event_data}" at {event.data}')
                            self.debug(f"Invalid data at {host}:{port}: {e}")

    def on_success_callback(self, event):
        source_scope_distance = event.get_source().scope_distance
        if source_scope_distance == 0 and event.scope_distance > 0:
            event.add_tag("affiliate")

    def visit_host(self, host, port):
        host = self.helpers.make_ip_type(host)
        netloc = self.helpers.make_netloc(host, port)
        host_hash = hash((host, port))
        dns_names = []
        emails = set()
        with self.ip_lock.get_lock(host_hash):
            with self.hosts_visited_lock:
                if host_hash in self.hosts_visited:
                    self.debug(f"Already processed {host} on port {port}, skipping")
                    return [], []
                else:
                    self.hosts_visited.add(host_hash)

            socket_type = socket.AF_INET
            if self.helpers.is_ip(host):
                if host.version == 6:
                    socket_type = socket.AF_INET6
            host = str(host)
            try:
                sock = socket.socket(socket_type, socket.SOCK_STREAM)
            except Exception as e:
                self.warning(f"Error creating socket for {netloc}: {e}. Do you have IPv6 disabled?")
                return [], []
            sock.settimeout(self.timeout)
            try:
                context = SSL.Context(PROTOCOL_TLSv1)
            except AttributeError as e:
                # AttributeError: module 'lib' has no attribute 'SSL_CTX_set_ecdh_auto'
                self.warning(f"Error creating SSL context: {e}")
                return [], []
            self.debug(f"Connecting to {host} on port {port}")
            try:
                sock.connect((host, port))
            except Exception as e:
                self.debug(f"Error connecting to {host} on port {port}: {e}")
                return [], []
            connection = SSL.Connection(context, sock)
            connection.set_tlsext_host_name(self.helpers.smart_encode(host))
            connection.set_connect_state()
            try:
                while 1:
                    try:
                        connection.do_handshake()
                    except SSL.WantReadError:
                        rd, _, _ = select.select([sock], [], [], sock.gettimeout())
                        if not rd:
                            raise SSL.Error("select timed out")
                        continue
                    break
            except Exception as e:
                self.debug(f"Error with SSL handshake on {host} port {port}: {e}")
                return [], []
            cert = connection.get_peer_certificate()
            sock.close()
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
        return dns_names, list(emails)

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
