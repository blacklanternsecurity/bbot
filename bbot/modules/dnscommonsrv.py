from bbot.modules.base import BaseModule

# the following are the result of a 1-day internet survey to find the top SRV records
# the scan resulted in 36,282 SRV records. the count for each one is shown.
common_srvs = [
    "_sipfederationtls._tcp",  # 6909
    "_sip._tls",  # 6853
    "_autodiscover._tcp",  # 4268
    "_xmpp-server._tcp",  # 1437
    "_sip._tcp",  # 1193
    "_sips._tcp",  # 1183
    "_caldavs._tcp",  # 1179
    "_carddavs._tcp",  # 1132
    "_caldav._tcp",  # 1035
    "_carddav._tcp",  # 1024
    "_sip._udp",  # 1007
    "_imaps._tcp",  # 1007
    "_submission._tcp",  # 906
    "_h323cs._tcp",  # 846
    "_h323ls._udp",  # 782
    "_xmpp-client._tcp",  # 689
    "_pop3s._tcp",  # 394
    "_jabber._tcp",  # 277
    "_imap._tcp",  # 267
    "_turn._udp",  # 256
    "_pop3._tcp",  # 221
    "_ldap._tcp",  # 213
    "_smtps._tcp",  # 195
    "_sipinternaltls._tcp",  # 192
    "_vlmcs._tcp",  # 165
    "_kerberos._udp",  # 163
    "_kerberos._tcp",  # 148
    "_kpasswd._udp",  # 128
    "_kpasswd._tcp",  # 100
    "_ntp._udp",  # 90
    "_gc._tcp",  # 73
    "_kerberos-master._udp",  # 66
    "_ldap._tcp.dc._msdcs",  # 63
    "_matrix._tcp",  # 62
    "_smtp._tcp",  # 61
    "_stun._udp",  # 57
    "_kerberos._tcp.dc._msdcs",  # 54
    "_ldap._tcp.gc._msdcs",  # 49
    "_kerberos-adm._tcp",  # 44
    "_ldap._tcp.pdc._msdcs",  # 43
    "_kerberos-master._tcp",  # 43
    "_http._tcp",  # 37
    "_h323rs._tcp",  # 36
    "_sipinternal._tcp",  # 35
    "_turn._tcp",  # 33
    "_stun._tcp",  # 33
    "_h323ls._tcp",  # 33
    "_x-puppet._tcp",  # 30
    "_h323cs._udp",  # 27
    "_stuns._tcp",  # 26
    "_jabber-client._tcp",  # 25
    "_x-puppet-ca._tcp",  # 22
    "_ts3._udp",  # 22
    "_minecraft._tcp",  # 22
    "_turns._tcp",  # 21
    "_ldaps._tcp",  # 21
    "_xmpps-client._tcp",  # 20
    "_https._tcp",  # 19
    "_ftp._tcp",  # 19
    "_xmpp-server._udp",  # 18
    "_xmpp-client._udp",  # 17
    "_jabber._udp",  # 17
    "_jabber-client._udp",  # 17
    "_xmpps-server._tcp",  # 15
    "_finger._tcp",  # 14
    "_stuns._udp",  # 12
    "_hkp._tcp",  # 12
    "_vlmcs._udp",  # 11
    "_turns._udp",  # 11
    "_tftp._udp",  # 11
    "_ssh._tcp",  # 11
    "_rtps._udp",  # 11
    "_mysqlsrv._tcp",  # 11
    "_hkps._tcp",  # 11
    "_h323be._udp",  # 11
    "_dns._tcp",  # 11
    "_wss._tcp",  # 10
    "_wpad._tcp",  # 10
    "_whois._tcp",  # 10
    "_webexconnect._tcp",  # 10
    "_webexconnects._tcp",  # 10
    "_vnc._tcp",  # 10
    "_test._tcp",  # 10
    "_telnet._tcp",  # 10
    "_telnets._tcp",  # 10
    "_teamspeak._tcp",  # 10
    "_svns._tcp",  # 10
    "_svcp._tcp",  # 10
    "_smb._tcp",  # 10
    "_sip-tls._tcp",  # 10
    "_sftp._tcp",  # 10
    "_secure-pop3._tcp",  # 10
    "_secure-imap._tcp",  # 10
    "_rtsp._tcp",  # 10
    "_rtps._tcp",  # 10
    "_rpc._tcp",  # 10
    "_rfb._tcp",  # 10
    "_raop._tcp",  # 10
    "_pstn._tcp",  # 10
    "_presence._tcp",  # 10
    "_pkixrep._tcp",  # 10
    "_pgprevokations._tcp",  # 10
    "_pgpkeys._tcp",  # 10
    "_ocsp._tcp",  # 10
    "_nntp._tcp",  # 10
    "_nfs._tcp",  # 10
    "_netbios-ssn._tcp",  # 10
    "_netbios-ns._tcp",  # 10
    "_netbios-dgm._tcp",  # 10
    "_mumble._tcp",  # 10
    "_msrpc._tcp",  # 10
    "_mqtts._tcp",  # 10
    "_minecraft._udp",  # 10
    "_iscsi._tcp",  # 10
    "_ircs._tcp",  # 10
    "_ipp._tcp",  # 10
    "_ipps._tcp",  # 10
    "_h323be._tcp",  # 10
    "_gits._tcp",  # 10
    "_ftps._tcp",  # 10
    "_ftpes._tcp",  # 10
    "_dnss._udp",  # 10
    "_dnss._tcp",  # 10
    "_diameter._tcp",  # 10
    "_crl._tcp",  # 10
    "_crls._tcp",  # 10
    "_cmp._tcp",  # 10
    "_certificates._tcp",  # 10
    "_aix._tcp",  # 10
    "_afpovertcp._tcp",  # 10
    "_collab-edge._tls",  # 6
    "_tcp",  # 5
    "_wildcard",  # 3
    "_client._smtp",  # 3
    "_udp",  # 2
    "_tls",  # 2
    "_msdcs",  # 2
    "_gc._msdcs",  # 2
    "_ldaps._tcp.dc._msdcs",  # 1
    "_kerberos._tcp.kdc._msdcs",  # 1
    "_kerberos.tcp.dc._msdcs",  # 1
    "_imap",  # 1
    "_iax",  # 1
]


class dnscommonsrv(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Check for common SRV records", "created_date": "2022-05-15", "author": "@TheTechromancer"}
    options = {"top": 50, "max_event_handlers": 10}
    options_desc = {
        "top": "How many of the top SRV records to check",
        "max_event_handlers": "How many instances of the module to run concurrently",
    }
    _max_event_handlers = 10

    def _incoming_dedup_hash(self, event):
        # dedupe by parent
        parent_domain = self.helpers.parent_domain(event.data)
        return hash(parent_domain), "already processed parent domain"

    async def filter_event(self, event):
        # skip SRV wildcards
        if "SRV" in await self.helpers.is_wildcard(event.host):
            return False
        return True

    async def handle_event(self, event):
        top = int(self.config.get("top", 50))
        parent_domain = self.helpers.parent_domain(event.data)
        queries = [f"{srv}.{parent_domain}" for srv in common_srvs[:top]]
        async for query, results in self.helpers.resolve_batch(queries, type="srv"):
            if results:
                await self.emit_event(query, "DNS_NAME", tags=["srv-record"], source=event)
