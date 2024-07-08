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
