from .base import BaseModule
from ssl import PROTOCOL_TLSv1
import select
import socket
from OpenSSL import SSL


class sslcert(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT"]
    produced_events = ["DNS_NAME"]
    options = {"timeout": 5.0}
    options_desc = {"timeout": "Socket connect timeout in seconds"}
    deps_pip = ["pyOpenSSL"]
    max_threads = 20

    def handle_event(self, event):

        port = 443
        host = str(event.data)

        if event.host and event.port:
            host, port = event.host, event.port

        cert_results = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout = self.config.get("timeout", 5.0)
        sock.settimeout(timeout)
        context = SSL.Context(PROTOCOL_TLSv1)
        try:
            sock.connect((host, port))
        except Exception as e:
            self.debug(f"Error connecting to {host} on port {port}: {e}")
            return
        connection = SSL.Connection(context, sock)
        connection.set_tlsext_host_name(host.encode())
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
            self.verbose(f"Error with SSL handshake on {host} port {port}: {e}")
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
            if c != host:
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
