import logging

from bbot.core.helpers.regexes import dns_name_regex
from bbot.core.helpers.misc import clean_dns_record, smart_decode

log = logging.getLogger("bbot.core.helpers.dns")


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


def extract_targets(record):
    """
    Extracts hostnames or IP addresses from a given DNS record.

    This method reads the DNS record's type and based on that, extracts the target
    hostnames or IP addresses it points to. The type of DNS record
    (e.g., "A", "MX", "CNAME", etc.) determines which fields are used for extraction.

    Args:
        record (dns.rdata.Rdata): The DNS record to extract information from.

    Returns:
        set: A set of tuples, each containing the DNS record type and the extracted value.

    Examples:
        >>> from dns.rrset import from_text
        >>> record = from_text('www.example.com', 3600, 'IN', 'A', '192.0.2.1')
        >>> extract_targets(record[0])
        {('A', '192.0.2.1')}

        >>> record = from_text('example.com', 3600, 'IN', 'MX', '10 mail.example.com.')
        >>> extract_targets(record[0])
        {('MX', 'mail.example.com')}

    """
    results = set()

    def add_result(rdtype, _record):
        cleaned = clean_dns_record(_record)
        if cleaned:
            results.add((rdtype, cleaned))

    rdtype = str(record.rdtype.name).upper()
    if rdtype in ("A", "AAAA", "NS", "CNAME", "PTR"):
        add_result(rdtype, record)
    elif rdtype == "SOA":
        add_result(rdtype, record.mname)
    elif rdtype == "MX":
        add_result(rdtype, record.exchange)
    elif rdtype == "SRV":
        add_result(rdtype, record.target)
    elif rdtype == "TXT":
        for s in record.strings:
            s = smart_decode(s)
            for match in dns_name_regex.finditer(s):
                start, end = match.span()
                host = s[start:end]
                add_result(rdtype, host)
    elif rdtype == "NSEC":
        add_result(rdtype, record.next)
    else:
        log.warning(f'Unknown DNS record type "{rdtype}"')
    return results


def service_record(host, rdtype=None):
    """
    Indicates that the provided host name and optional rdtype is an SRV or related service record.

    These types of records do/should not have A/AAAA/CNAME or similar records, and are simply used to advertise configuration information and/or policy information for different Internet facing services.

    This function exists to provide a consistent way in which to perform this test, rather than having duplicated code in multiple places in different modules.

    The response provides a way for modules to quickly test whether a host name is relevant and worth inspecting or using in context of what the module does.

    NOTE: While underscores are technically not supposed to exist in DNS names as per RFC's, they can be used, so we can't assume that a name that contains or starts with an underscore is a service record and so must check for specific strings.

    Args:
        host (string): A DNS host name

    Returns:
        bool: A boolean, True indicates that the host is an SRV or similar record, False indicates that it is not.

    Examples:
        >>> service_record('_xmpp._tcp.example.com')
        True

        >>> service_record('_custom._service.example.com', 'SRV')
        True

        >>> service_record('_dmarc.example.com')
        True

        >>> service_record('www.example.com')
        False
    """

    # if we were providing an rdtype, check if it is SRV
    # NOTE: we don't care what the name is if rdtype == SRV
    if rdtype and str(rdtype).upper() == "SRV":
        return True

    # we did not receive rdtype, so we'll have to inspect host name parts
    parts = str(host).split(".")

    if not parts:
        return False

    # DMARC TXT records, e.g. _dmarc.example.com
    if parts[0] == "_dmarc":
        return True

    # MTA-STS TXT records, e.g. _mta-sts.example.com
    if parts[0] == "_mta-sts":
        return True

    if len(parts) < 2:
        return False

    # classic SRV record names, e.g. _ldap._tcp.example.com
    if parts[1] == "_udp" or parts[1] == "_tcp":
        return True

    # TLS indicating records, used by SMTP TLS-RPT etc, e.g. _smtp._tls.example.com
    if parts[1] == "_tls":
        return True

    # BIMI TXT records, e.g. selector._bimi.example.com
    if parts[1] == "_bimi":
        return True

    # DKIM TXT records, e.g. selector._domainkey.example.com
    if parts[1] == "_domainkey":
        return True

    return False
