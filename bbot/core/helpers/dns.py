import dns.resolver

from .misc import is_ip


def resolve(query, **kwargs):
    """
    Arguments:
        type: query type (A, AAAA, MX, etc.)
    """
    query = str(query)
    if is_ip(query):
        return _resolve_ip(query, **kwargs)
    else:
        kwargs["rdtype"] = kwargs.pop("type", "A")
        return _resolve_hostname(query, **kwargs)


def _resolve_hostname(query, **kwargs):
    answers = set()
    for ip in list(dns.resolver.resolve(query, **kwargs)):
        answers.add(str(ip))
    return list(answers)


def _resolve_ip(query, **kwargs):
    answers = set()
    for host in list(dns.resolver.resolve_address(query, **kwargs)):
        answers.add(str(host).lower())
    return list(answers)
