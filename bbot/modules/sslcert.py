import select
import socket
import threading
from OpenSSL import SSL
from ssl import PROTOCOL_TLSv1

from .base import BaseModule


class sslcert(BaseModule):

    flags = ["subdomain-enum", "active"]
    watched_events = ["DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT"]
    produced_events = ["DNS_NAME"]
    options = {"timeout": 5.0}
    options_desc = {"timeout": "Socket connect timeout in seconds"}
    deps_apt = ["openssl"]
    deps_pip = ["pyOpenSSL"]
    max_threads = 20

    def setup(self):
        self.hosts_visited = set()
        self.hosts_visited_lock = threading.Lock()
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

        for host in hosts:
            host = self.helpers.make_ip_type(host)
            host_hash = hash((host, port))
            with self.hosts_visited_lock:
                if host_hash in self.hosts_visited:
                    self.debug(f"Already processed {host} on port {port}, skipping")
                    return
                else:
                    self.hosts_visited.add(host_hash)

            cert_results = []
            socket_type = socket.AF_INET
            if self.helpers.is_ip(host):
                if host.version == 6:
                    socket_type = socket.AF_INET6
            host = str(host)
            sock = socket.socket(socket_type, socket.SOCK_STREAM)
            timeout = self.config.get("timeout", 5.0)
            sock.settimeout(timeout)
            context = SSL.Context(PROTOCOL_TLSv1)
            self.debug(f"Connecting to {host} on port {port}")
            try:
                sock.connect((host, port))
            except Exception as e:
                self.debug(f"Error connecting to {host} on port {port}: {e}")
                return
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
                            raise timeout("select timed out")
                        continue
                    break
            except Exception as e:
                self.debug(f"Error with SSL handshake on {host} port {port}: {e}")
                return
            cert = connection.get_peer_certificate()
            sock.close()
            subject = cert.get_subject().commonName
            sans = self.get_cert_sans(cert)

            cert_results.append(str(subject).lstrip("*.").lower())
            for san in sans:
                san = san.lstrip("*.").lower()
                cert_results.append(san)
            for c in set(cert_results):
                if c != _host:
                    self.debug(f"Discovered new domain via SSL certificate parsing: [{c}]")
                    if self.helpers.is_ip(c):
                        self.emit_event(c, "IP_ADDRESS", event)
                    else:
                        self.emit_event(c, "DNS_NAME", event)

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
                hostname = raw_san.split(":")[-1].strip()
                sans.append(hostname)
        return sans
