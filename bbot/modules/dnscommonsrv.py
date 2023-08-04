from bbot.modules.base import BaseModule

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
    "_smtp._tcp",
    # MailEnable
    "_caldav._tcp",
    "_caldavs._tcp",
    "_carddav._tcp",
    "_carddavs._tcp",
    # STUN
    "_stun._tcp",
    "_stun._udp",
    "_stuns._tcp",
    "_turn._tcp",
    "_turn._udp",
    "_turns._tcp",
    # SIP
    "_h323be._tcp",
    "_h323be._udp",
    "_h323cs._tcp",
    "_h323cs._udp",
    "_h323ls._tcp",
    "_h323ls._udp",
    "_sip._tcp",
    "_sip._tls",
    "_sip._udp",
    "_sipfederationtls._tcp",
    "_sipinternal._tcp",
    "_sipinternaltls._tcp",
    "_sips._tcp",
    # misc
    "_aix._tcp",
    "_certificates._tcp",
    "_cmp._tcp",
    "_crl._tcp",
    "_crls._tcp",
    "_finger._tcp",
    "_ftp._tcp",
    "_gc._tcp",
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
    "_submission._tcp",
    "_svcp._tcp",
    "_telnet._tcp",
    "_test._tcp",
    "_whois._tcp",
    "_x-puppet-ca._tcp",
    "_x-puppet._tcp",
    "_xmpp-client._tcp",
    "_xmpp-client._udp",
    "_xmpp-server._tcp",
    "_xmpp-server._udp",
]


class dnscommonsrv(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Check for common SRV records"}
    max_event_handlers = 5

    async def filter_event(self, event):
        # skip SRV wildcards
        if "SRV" in await self.helpers.is_wildcard(event.host):
            return False
        return True

    async def handle_event(self, event):
        queries = [event.data] + [f"{srv}.{event.data}" for srv in common_srvs]
        async for query, results in self.helpers.resolve_batch(queries, type="srv"):
            if results:
                self.emit_event(query, "DNS_NAME", tags=["srv-record"], source=event)
