import re
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

# Designed to remove junk such as these from the beginning of a search string:
# \nhttps://www.google.com
# \x3dhttps://www.google.com
# %a2https://www.google.com
# \uac20https://www.google.com
junk_remover = r"(?:\\x[a-fA-F0-9]{2}|%[a-fA-F0-9]{2}|\\u[a-fA-F0-9]{4}|\\[a-zA-Z])?"

word_regex = re.compile(r"[^\d\W_]+")
word_num_regex = re.compile(r"[^\W_]+")
num_regex = re.compile(r"\d+")
_ipv6_regex = r"[A-F0-9:]*:[A-F0-9:]*:[A-F0-9:]*"
ipv6_regex = re.compile(_ipv6_regex, re.I)
_dns_name_regex = r"(?:(?:[\w-]+)\.)+(?:[^\W_0-9]{2,20})"
_hostname_regex = re.compile(r"^[\w-]+$")
_email_regex = r"(?:[^\W_][\w\-\.\+]{,100})@(?:\w[\w\-\._]{,100})\.(?:[^\W_0-9]{2,8})"
email_regex = re.compile(_email_regex, re.I)

event_type_regexes = OrderedDict(
    [
        (k, tuple(re.compile(r, re.I) for r in regexes))
        for k, regexes in [
            (
                "DNS_NAME",
                (r"^" + _dns_name_regex + r"$",),
            ),
            (
                "EMAIL_ADDRESS",
                (r"^" + _email_regex + r"$",),
            ),
            (
                "OPEN_TCP_PORT",
                (
                    r"^((?:\w|\w[\w\-]*\w)[\.]?)+(?:\w[\w\-]*\w|\w):[0-9]{1,5}$",
                    r"^\[" + _ipv6_regex + r"\]:[0-9]{1,5}$",
                ),
            ),
            (
                "URL",
                (
                    r"https?://((?:\w|\w[\w\-]*\w)[\.]?)+(?:\w[\w\-]*\w|\w)(?::[0-9]{1,5})?.*$",
                    r"https?://\[" + _ipv6_regex + r"\](?::[0-9]{1,5})?.*$",
                ),
            ),
        ]
    ]
)

event_id_regex = re.compile(r"[0-9a-f]{40}:[A-Z0-9_]+")
dns_name_regex = re.compile(_dns_name_regex, re.I)
scan_name_regex = re.compile(r"[a-z]{3,20}_[a-z]{3,20}")
