import re
from collections import OrderedDict

# for extracting words from strings
word_regexes = [
    re.compile(r, re.I)
    for r in [
        # alphanumeric, underscore
        r"[\w]+",
        # alphanumeric, underscore, dash
        r"[\w-]+",
        # alpha
        r"[a-z]{3,}",
        # alpha, dash
        r"[a-z]+[a-z-]+[a-z]+",
        # alpha, underscore
        r"[a-z]+[a-z_]+[a-z]+",
        # alpha, underscore, dash
        r"[a-z]+[a-z_-]+[a-z]+",
    ]
]


word_regex = re.compile(r"[^\d\W_]+")
word_num_regex = re.compile(r"[^\W_]+")
num_regex = re.compile(r"\d+")
_dns_name_regex = r"(([A-Z0-9\-_]+)\.)+([A-Z0-9\-_]+)"


# todo: detect ipv6 addresses in OPEN_TCP_PORT and URL
event_type_regexes = OrderedDict(
    [
        (k, re.compile(r, re.I))
        for k, r in [
            (
                "EMAIL_ADDRESS",
                r"^([A-Z0-9][\w\-\.\+]{,100})@([A-Z0-9][\w\-\.]{,100})\.([A-Z]{2,8})$",
            ),
            (
                "DNS_NAME",
                rf"^{_dns_name_regex}$",
            ),
            (
                "OPEN_TCP_PORT",
                r"^(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)+([A-Z0-9][A-Z0-9\-]*[A-Z0-9]|[A-Z0-9]):[0-9]{1,5}$",
            ),
            (
                "URL",
                r"^([A-Z]){2,}://(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)+([A-Z0-9][A-Z0-9\-]*[A-Z0-9]|[A-Z0-9])(:[0-9]{1,5}){0,1}.*$",
            ),
        ]
    ]
)

event_id_regex = re.compile(r"[0-9a-f]{40}:[A-Z0-9_]+")
dns_name_regex = re.compile(_dns_name_regex, re.I)
