"""Build HTTP_RESPONSE event data dicts from blasthttp.Response objects.

Materializes hash and cert_info eagerly, so only call when about to emit an
HTTP_RESPONSE event (otherwise blasthttp.Response stays lazy).
"""

import re
from urllib.parse import urlparse


_TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def response_to_event_dict(response, url_input, method="GET"):
    """Convert a blasthttp.Response into the dict format HTTP_RESPONSE events expect.

    Args:
        response: a blasthttp.Response (native 0.5+ object with .hash, .cert_info)
        url_input: the original scan-target identifier (host:port or full URL)
        method: HTTP method used to fetch the response

    Returns:
        dict with keys url, input, status_code, method, path, host, raw_header,
        header, content_type, content_length, title, body, location, hash. Adds
        cert_info when the response carried a TLS certificate.
    """
    parsed = urlparse(response.url)
    path = parsed.path or "/"

    status_line = f"HTTP/1.1 {response.status} \r\n"
    raw_header = f"{status_line}{response.raw_headers}\r\n\r\n"

    header_dict = {}
    for k, v in response.headers.items():
        key = k.lower().replace("-", "_")
        if key in header_dict:
            header_dict[key] += f", {v}"
        else:
            header_dict[key] = v

    content_type = header_dict.get("content_type", "")
    content_length = int(header_dict.get("content_length", len(response.body_bytes)))
    location = header_dict.get("location", "")

    body = response.body
    title = ""
    title_match = _TITLE_REGEX.search(body)
    if title_match:
        title = title_match.group(1).strip()

    j = {
        "url": response.url,
        "input": url_input,
        "status_code": response.status,
        "method": method,
        "path": path,
        "host": parsed.hostname or "",
        "raw_header": raw_header,
        "header": header_dict,
        "content_type": content_type,
        "content_length": content_length,
        "title": title,
        "body": body,
        "location": location,
        "hash": {
            "body_md5": response.hash.body_md5,
            "body_mmh3": response.hash.body_mmh3,
            "body_sha256": response.hash.body_sha256,
            "header_md5": response.hash.header_md5,
            "header_mmh3": response.hash.header_mmh3,
            "header_sha256": response.hash.header_sha256,
        },
    }

    ci = response.cert_info
    if ci is not None:
        j["cert_info"] = {
            "common_name": ci.common_name,
            "sans": ci.sans,
            "emails": ci.emails,
            "issuer": ci.issuer,
            "not_before": ci.not_before,
            "not_after": ci.not_after,
            "fingerprint_sha256": ci.fingerprint_sha256,
        }

    return j
