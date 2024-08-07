import logging

from bbot.core.helpers.regexes import dns_name_regex
from bbot.core.helpers.misc import clean_dns_record, smart_decode

log = logging.getLogger("bbot.core.helpers.dns")


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

    # DMARC TXT records, e.g. _dmarc.example.com
    if parts[0] == "_dmarc":
        return True

    # MTA-STS TXT records, e.g. _mta-sts.example.com
    if parts[0] == "_mta-sts":
        return True

    return False
