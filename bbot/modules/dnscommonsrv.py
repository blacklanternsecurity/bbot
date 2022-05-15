from .base import BaseModule


class dnscommonsrv(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    in_scope_only = True

    common_srvs = [
        # Micro$oft
        "_ldap._tcp.dc._msdcs",
        "_ldap._tcp.gc._msdcs",
        "_ldap._tcp.pdc._msdcs",
        "_ldap._tcp",
        "_ldap._tcp.ForestDNSZones",
        "_gc._msdcs",
        "_kpasswd._tcp",
        "_kpasswd._udp",
        "_kerberos._tcp.dc._msdcs",
        "_kerberos.tcp.dc._msdcs",
        "_kerberos-master._tcp",
        "_kerberos-master._udp",
        "_kerberos._tcp",
        "_kerberos._udp",
        "_autodiscover._tcp",
        # NTP
        "_ntp._udp",
        # mDNS
        "_nntp._tcp",
        # email
        "_imap._tcp",
        "_imap.tcp",
        "_imaps._tcp",
        "_pop3._tcp",
        "_pop3s._tcp",
        # misc
        "_aix._tcp",
        "_caldav._tcp",
        "_caldavs._tcp",
        "_carddav._tcp",
        "_carddavs._tcp",
        "_certificates._tcp",
        "_cmp._tcp",
        "_crl._tcp",
        "_crls._tcp",
        "_finger._tcp",
        "_ftp._tcp",
        "_gc._tcp",
        "_h323be._tcp",
        "_h323be._udp",
        "_h323cs._tcp",
        "_h323cs._udp",
        "_h323ls._tcp",
        "_h323ls._udp",
        "_hkp._tcp",
        "_hkps._tcp",
        "_http._tcp",
        "_https._tcp",
        "_jabber-client._tcp",
        "_jabber-client._udp",
        "_jabber._tcp",
        "_jabber._udp",
        "_ocsp._tcp",
        "_pgpkeys._tcp",
        "_pgprevokations._tcp",
        "_PKIXREP._tcp",
        "_sip._tcp",
        "_sip._tls",
        "_sip._udp",
        "_sipfederationtls._tcp",
        "_sipinternal._tcp",
        "_sipinternaltls._tcp",
        "_sips._tcp",
        "_smtp._tcp",
        "_stun._tcp",
        "_stun._udp",
        "_stuns._tcp",
        "_submission._tcp",
        "_svcp._tcp",
        "_telnet._tcp",
        "_test._tcp",
        "_turn._tcp",
        "_turn._udp",
        "_turns._tcp",
        "_whois._tcp",
        "_x-puppet-ca._tcp",
        "_x-puppet._tcp",
        "_xmpp-client._tcp",
        "_xmpp-client._udp",
        "_xmpp-server._tcp",
        "_xmpp-server._udp",
    ]

    def handle_event(self, event):
        queries = [event.data] + [f"{srv}.{event.data}" for srv in self.common_srvs]
        for query, results in self.helpers.resolve_batch(*queries, type="srv"):
            if results:
                srv_event = self.scan.make_event(query, "DNS_NAME", tags=["dns_srv"], source=event)
                self.emit_event(srv_event)
                for result in results:
                    dns_target = result.split()[-1].rstrip(".")
                    if self.helpers.is_dns_name(dns_target):
                        self.emit_event(dns_target, "DNS_NAME", source=srv_event)
