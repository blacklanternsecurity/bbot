import regex as re
from collections import OrderedDict

# for extracting words from strings
word_regexes = [
    re.compile(r, re.I)
    for r in [
        # alpha
        r"[a-z]{3,}",
        # alphanum
        r"[a-z0-9]{3,}",
        # alpha, dash
        r"[a-z][a-z-]+[a-z]",
        # alpha, underscore
        r"[a-z][a-z_]+[a-z]",
    ]
]

word_regex = re.compile(r"[^\d\W_]+")
word_num_regex = re.compile(r"[^\W_]+")
num_regex = re.compile(r"\d+")

_ipv4_regex = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
ipv4_regex = re.compile(_ipv4_regex, re.I)

# IPv6 is complicated, so we have accommodate alternative patterns,
# :(:[A-F0-9]{1,4}){1,7} == ::1, ::ffff:1
# ([A-F0-9]{1,4}:){1,7}: == 2001::, 2001:db8::, 2001:db8:0:1:2:3::
# ([A-F0-9]{1,4}:){1,6}:([A-F0-9]{1,4}) == 2001::1, 2001:db8::1, 2001:db8:0:1:2:3::1
# ([A-F0-9]{1,4}:){7,7}([A-F0-9]{1,4}) == 1:1:1:1:1:1:1:1, ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

_ipv6_regex = r"(:(:[A-F0-9]{1,4}){1,7}|([A-F0-9]{1,4}:){1,7}:|([A-F0-9]{1,4}:){1,6}:([A-F0-9]{1,4})|([A-F0-9]{1,4}:){7,7}([A-F0-9]{1,4}))"
ipv6_regex = re.compile(_ipv6_regex, re.I)

_ip_range_regexes = (
    _ipv4_regex + r"\/[0-9]{1,2}",
    _ipv6_regex + r"\/[0-9]{1,3}",
)
ip_range_regexes = [re.compile(r, re.I) for r in _ip_range_regexes]

# all dns names including IP addresses and bare hostnames (e.g. "localhost")
_dns_name_regex = r"(?:\w(?:[\w-]{0,100}\w)?\.?)+(?:[xX][nN]--)?[^\W_]{1,63}\.?"
# dns names with periods (e.g. "www.example.com")
_dns_name_regex_with_period = r"(?:\w(?:[\w-]{0,100}\w)?\.)+(?:[xX][nN]--)?[^\W_]{1,63}\.?"

dns_name_extraction_regex = re.compile(_dns_name_regex_with_period, re.I)
dns_name_validation_regex = re.compile(r"^" + _dns_name_regex + r"$", re.I)

_email_regex = r"(?:[^\W_][\w\-\.\+']{,100})@" + _dns_name_regex
email_regex = re.compile(_email_regex, re.I)

_ptr_regex = r"(?:[0-9]{1,3}[-_\.]){3}[0-9]{1,3}"
ptr_regex = re.compile(_ptr_regex)
# uuid regex
_uuid_regex = r"[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}"
uuid_regex = re.compile(_uuid_regex, re.I)
# event uuid regex
_event_uuid_regex = r"[0-9A-Z_]+:[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}"
event_uuid_regex = re.compile(_event_uuid_regex, re.I)

_open_port_regexes = (
    _dns_name_regex + r":[0-9]{1,5}",
    r"\[" + _ipv6_regex + r"\]:[0-9]{1,5}",
)
open_port_regexes = [re.compile(r, re.I) for r in _open_port_regexes]

_url_regexes = (
    r"https?://" + _dns_name_regex + r"(?::[0-9]{1,5})?(?:(?:/|\?).*)?",
    r"https?://\[" + _ipv6_regex + r"\](?::[0-9]{1,5})?(?:(?:/|\?).*)?",
)
url_regexes = [re.compile(r, re.I) for r in _url_regexes]

_double_slash_regex = r"/{2,}"
double_slash_regex = re.compile(_double_slash_regex)

# event type regexes, used throughout BBOT for autodetection of event types, validation, and excavation.
event_type_regexes = OrderedDict(
    (
        (k, tuple(re.compile(r, re.I) for r in regexes))
        for k, regexes in (
            (
                "DNS_NAME",
                (r"^" + _dns_name_regex + r"$",),
            ),
            (
                "EMAIL_ADDRESS",
                (r"^" + _email_regex + r"$",),
            ),
            (
                "IP_ADDRESS",
                (
                    r"^" + _ipv4_regex + r"$",
                    r"^" + _ipv6_regex + r"$",
                ),
            ),
            (
                "IP_RANGE",
                tuple(r"^" + r + r"$" for r in _ip_range_regexes),
            ),
            (
                "OPEN_TCP_PORT",
                tuple(r"^" + r + r"$" for r in _open_port_regexes),
            ),
            (
                "URL",
                tuple(r"^" + r + r"$" for r in _url_regexes),
            ),
        )
    )
)

scan_name_regex = re.compile(r"[a-z]{3,20}_[a-z]{3,20}")


# For use with excavate parameters extractor
input_tag_regex = re.compile(
    r"<input[^>]+?name=[\"\']?([\.$\w]+)[\"\']?(?:[^>]*?value=[\"\']([=+\/\w]*)[\"\'])?[^>]*>"
)
jquery_get_regex = re.compile(r"url:\s?[\"\'].+?\?(\w+)=")
jquery_post_regex = re.compile(r"\$.post\([\'\"].+[\'\"].+\{(.+)\}")
a_tag_regex = re.compile(r"<a[^>]*href=[\"\']([^\"\'?>]*)\?([^&\"\'=]+)=([^&\"\'=]+)")
img_tag_regex = re.compile(r"<img[^>]*src=[\"\']([^\"\'?>]*)\?([^&\"\'=]+)=([^&\"\'=]+)")
get_form_regex = re.compile(
    r"<form[^>]+(?:action=[\"']?([^\s\'\"]+)[\"\']?)?[^>]*method=[\"']?[gG][eE][tT][\"']?[^>]*>([\s\S]*?)<\/form>",
    re.DOTALL,
)
post_form_regex = re.compile(
    r"<form[^>]+(?:action=[\"']?([^\s\'\"]+)[\"\']?)?[^>]*method=[\"']?[pP][oO][sS][tT][\"']?[^>]*>([\s\S]*?)<\/form>",
    re.DOTALL,
)
select_tag_regex = re.compile(
    r"<select[^>]+?name=[\"\']?(\w+)[\"\']?[^>]*>(?:\s*<option[^>]*?value=[\"\'](\w*)[\"\']?[^>]*>)?"
)
textarea_tag_regex = re.compile(
    r'<textarea[^>]*\bname=["\']?(\w+)["\']?[^>]*>(.*?)</textarea>', re.IGNORECASE | re.DOTALL
)
tag_attribute_regex = re.compile(r"<[^>]*(?:href|action|src)\s*=\s*[\"\']?(?!mailto:)([^\s\'\"\>]+)[\"\']?[^>]*>")

valid_netloc = r"[^\s!@#$%^&()=/?\\'\";~`<>]+"

_split_host_port_regex = r"(?:(?P<scheme>[a-z0-9]{1,20})://)?(?:[^?]*@)?(?P<netloc>" + valid_netloc + ")"
split_host_port_regex = re.compile(_split_host_port_regex, re.I)

_extract_open_port_regex = r"(?:(?:\[([0-9a-f:]+)\])|([^\s:]+))(?::(\d{1,5}))?"
extract_open_port_regex = re.compile(_extract_open_port_regex)

_extract_host_regex = r"(?:[a-z0-9]{1,20}://)?(?:[^?]*@)?(" + valid_netloc + ")"
extract_host_regex = re.compile(_extract_host_regex, re.I)

# for use in recursive_decode()
encoded_regex = re.compile(r"%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\[ntrbv]")
backslash_regex = re.compile(r"(?P<slashes>\\+)(?P<char>[ntrvb])")

uuid_regex = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
