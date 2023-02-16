import select
import socket
import threading
from OpenSSL import SSL
from ssl import PROTOCOL_TLSv1

from bbot.modules.base import BaseModule
from bbot.core.errors import ValidationError
from bbot.core.helpers.threadpool import NamedLock


class sslcert(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS"]
    flags = ["affiliates", "subdomain-enum", "email-enum", "active", "safe"]
    meta = {
        "description": "Visit open ports and retrieve SSL certificates",
    }
    options = {"timeout": 5.0, "skip_non_ssl": True}
    options_desc = {"timeout": "Socket connect timeout in seconds", "skip_non_ssl": "Don't try common non-SSL ports"}
    deps_apt = ["openssl"]
    deps_pip = ["pyOpenSSL"]
    max_threads = 50
    max_event_handlers = 25
    scope_distance_modifier = 0
    _priority = 2

    def setup(self):
        self.timeout = self.config.get("timeout", 5.0)
        self.skip_non_ssl = self.config.get("skip_non_ssl", True)
        self.non_ssl_ports = (22, 53, 80)

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

        for future in self.helpers.as_completed(futures):
            host = futures[future]
            for event_type, event_data in future.result():
                if event_data is not None and event_data != event:
                    self.debug(f"Discovered new {event_type} via SSL certificate parsing: [{event_data}]")
                    try:
                        ssl_event = self.make_event(event_data, event_type, source=event, raise_error=True)
                        if ssl_event:
                            self.emit_event(ssl_event)
                    except ValidationError as e:
                        self.hugeinfo(f'Malformed {event_type} "{event_data}" at {event.data}')
                        self.debug(f"Invalid data at {host}:{port}: {e}")

    def visit_host(self, host, port):
        host = self.helpers.make_ip_type(host)
        host_hash = hash((host, port))
        results = []
        with self.ip_lock.get_lock(host_hash):
            with self.hosts_visited_lock:
                if host_hash in self.hosts_visited:
                    self.debug(f"Already processed {host} on port {port}, skipping")
                    return results
                else:
                    self.hosts_visited.add(host_hash)

            socket_type = socket.AF_INET
            if self.helpers.is_ip(host):
                if host.version == 6:
                    socket_type = socket.AF_INET6
            host = str(host)
            sock = socket.socket(socket_type, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            context = SSL.Context(PROTOCOL_TLSv1)
            self.debug(f"Connecting to {host} on port {port}")
            try:
                sock.connect((host, port))
            except Exception as e:
                self.debug(f"Error connecting to {host} on port {port}: {e}")
                return results
            connection = SSL.Connection(context, sock)
            connection.set_tlsext_host_name(self.helpers.smart_encode(host))
            connection.set_connect_state()
            try:
                while True:
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
                return results
            cert = connection.get_peer_certificate()
            sock.close()
            issuer = cert.get_issuer()
            if issuer.emailAddress and self.helpers.regexes.email_regex.match(issuer.emailAddress):
                results.append(("EMAIL_ADDRESS", issuer.emailAddress))
            subject = cert.get_subject()
            if subject.emailAddress and self.helpers.regexes.email_regex.match(subject.emailAddress):
                results.append(("EMAIL_ADDRESS", subject.emailAddress))
            common_name = subject.commonName
            cert_results = self.get_cert_sans(cert)
            cert_results.append(str(common_name).lstrip("*.").lower())
            for c in set(cert_results):
                results.append(("DNS_NAME", c))
        return results

    @staticmethod
    def get_cert_sans(cert):
        sans = []
        raw_sans = None
        ext_count = cert.get_extension_count()
        for i in range(0, ext_count):
            ext = cert.get_extension(i)
            if "subjectAltName" in str(ext.get_short_name()):
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
