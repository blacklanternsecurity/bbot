import logging
import ipaddress

from bbot.core.helpers import regexes
from bbot.core.helpers.url import clean_url
from bbot.core.helpers.punycode import smart_decode_punycode
from bbot.core.helpers.misc import split_host_port, make_netloc

log = logging.getLogger("bbot.core.helpers.")


def validator(func):
    """
    Decorator for squashing all errors into ValueError
    """

    def validate_wrapper(*args, **kwargs):
        try:
            return func(*args)
        except Exception as e:
            raise ValueError(f"Validation failed for {args}, {kwargs}: {e}")

    return validate_wrapper


@validator
def validate_port(port):
    return max(1, min(65535, int(str(port))))


@validator
def validate_open_port(open_port):
    host, port = split_host_port(open_port)
    port = validate_port(port)
    host = validate_host(host)
    if host and port:
        return make_netloc(host, port)


@validator
def validate_host(host):
    # stringify, strip and lowercase
    host = str(host).strip().lower()
    # handle IPv6 netlocs
    if host.startswith("["):
        host = host.split("[")[-1].split("]")[0]
    try:
        # try IPv6 first
        ip = ipaddress.IPv6Address(host)
        return str(ip)
    except Exception:
        # if IPv6 fails, strip ports and root zone
        host = host.split(":")[0].rstrip(".")
        try:
            ip = ipaddress.IPv4Address(host)
            return str(ip)
        except Exception:
            # finally, try DNS_NAME
            host = smart_decode_punycode(host.lstrip("*."))
            for r in regexes.event_type_regexes["DNS_NAME"]:
                if r.match(host):
                    return host
            if regexes._hostname_regex.match(host):
                return host
    assert False, f'Invalid hostname: "{host}"'


@validator
def validate_url(url):
    return validate_url_parsed(url).geturl()


@validator
def validate_url_parsed(url):
    url = str(url).strip()
    if not any(r.match(url) for r in regexes.event_type_regexes["URL"]):
        assert False, f'Invalid URL: "{url}"'
    return clean_url(url)


@validator
def validate_severity(severity):
    severity = str(severity).strip().upper()
    if not severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError(f"Invalid severity: {severity}")
    return severity


@validator
def validate_email(email):
    email = smart_decode_punycode(str(email).strip().lower())
    if any(r.match(email) for r in regexes.event_type_regexes["EMAIL_ADDRESS"]):
        return email
    assert False, f'Invalid email: "{email}"'


def soft_validate(s, t):
    """
    Friendly validation wrapper that returns True/False instead of raising an error

    is_valid_url = soft_validate("http://evilcorp.com", "url")
    is_valid_host = soft_validate("http://evilcorp.com", "host")
    """
    try:
        validator_fn = globals()[f"validate_{t.strip().lower()}"]
    except KeyError:
        raise ValueError(f'No validator for type "{t}"')
    try:
        validator_fn(s)
        return True
    except ValueError:
        return False
