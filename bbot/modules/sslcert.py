from .base import BaseModule
from ssl import PROTOCOL_TLSv1
import socket
from OpenSSL import SSL


class sslcert(BaseModule):

    watched_events = ["HOSTNAME", "IPV6_ADDRESS", "IPV4_ADDRESS"]
    produced_events = ["HOSTNAME"]
    max_threads = 10

    def handle_event(self, event):
        # only process targets
        if not event in self.scan.target:
            return

        port = 443
        host = str(event.data)

        if event.type == "OPEN_PORT":
            host, port = event.data.split(":")

        cert_results = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = SSL.Context(PROTOCOL_TLSv1)
        sock.connect((host, port))
        connection = SSL.Connection(context, sock)
        connection.set_tlsext_host_name(host.encode())
        connection.set_connect_state()
        connection.do_handshake()
        cert = connection.get_peer_certificate()
        sock.close()
        subject = cert.get_subject().commonName
        sans = self.get_cert_sans(cert)

        cert_results.append(str(subject))
        for san in sans:
            san = san.lstrip("*.").lower()
            cert_results.append(san)
        for c in set(cert_results):
            if c != host:
                self.debug(f"Discovered new domain via SSL certificate parsing: [{c}]")
                self.emit_event(c, "HOSTNAME", event)

    @staticmethod
    def get_cert_sans(cert):

        sans = []
        ext_count = cert.get_extension_count()
        for i in range(0, ext_count):
            ext = cert.get_extension(i)
            if "subjectAltName" in str(ext.get_short_name()):
                raw_sans = str(ext)
        for raw_san in raw_sans.split(","):
            sans.append(raw_san.split(":")[-1].strip())
        return sans
