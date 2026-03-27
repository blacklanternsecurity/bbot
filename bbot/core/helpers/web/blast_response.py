"""
Response wrapper that gives blasthttp responses a standard Python interface.

BBOT modules see .status_code, .text, .content, .headers, .json(),
.raise_for_status() — the same interface they've always used. The wrapper
copies data out of the blasthttp PyO3 object into plain Python types so
nothing holds a reference to the Rust-side response after construction.
"""

import json as _json
from collections.abc import MutableMapping as _MutableMapping
from datetime import timedelta as _timedelta


class CaseInsensitiveHeaders(_MutableMapping):
    """
    Case-insensitive dict-like object for HTTP headers.

    Modules access headers case-insensitively, they do things like
    response.headers.get("Content-Type") or response.headers["content-type"].
    This replicates that behavior using a simple list of (name, value) tuples
    as the backing store (preserving duplicates like Set-Cookie).

    Supports mutation (del, __setitem__) for compatibility with HttpCompare.
    """

    __slots__ = ("_list", "_lower_dict")

    def __init__(self, header_tuples):
        self._list = list(header_tuples)
        self._rebuild_dict()

    def _rebuild_dict(self):
        # Last value wins for dict-style access
        self._lower_dict = {}
        for k, v in self._list:
            self._lower_dict[k.lower()] = v

    def get(self, key, default=None):
        return self._lower_dict.get(key.lower(), default)

    def items(self):
        return iter(self._list)

    def keys(self):
        return self._lower_dict.keys()

    def values(self):
        return self._lower_dict.values()

    def __getitem__(self, key):
        try:
            return self._lower_dict[key.lower()]
        except KeyError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        # Remove any existing entries with this key (case-insensitive)
        lower_key = key.lower()
        self._list = [(k, v) for k, v in self._list if k.lower() != lower_key]
        self._list.append((key, value))
        self._lower_dict[lower_key] = value

    def __delitem__(self, key):
        lower_key = key.lower()
        if lower_key not in self._lower_dict:
            raise KeyError(key)
        self._list = [(k, v) for k, v in self._list if k.lower() != lower_key]
        del self._lower_dict[lower_key]

    def __contains__(self, key):
        return key.lower() in self._lower_dict

    def __iter__(self):
        return iter(self._lower_dict)

    def __len__(self):
        return len(self._lower_dict)

    def __eq__(self, other):
        if isinstance(other, CaseInsensitiveHeaders):
            return self._lower_dict == other._lower_dict
        if isinstance(other, dict):
            return self._lower_dict == {k.lower(): v for k, v in other.items()}
        return NotImplemented

    def __repr__(self):
        return f"CaseInsensitiveHeaders({self._list})"


class _RequestInfo:
    """Minimal stand-in for a response.request object."""

    __slots__ = ("url", "method")

    def __init__(self, url, method):
        self.url = url
        self.method = method


class BlasthttpResponse:
    """
    Wraps data extracted from a blasthttp Response into a standard
    interface so BBOT modules work without changes.

    All fields are plain Python types (str, bytes, int, dict) — no references
    to blasthttp PyO3 objects are retained after construction.
    """

    __slots__ = (
        "status_code",
        "url",
        "text",
        "content",
        "headers",
        "request",
        "is_success",
        "elapsed_ms",
        "cookies",
    )

    def __init__(self, blast_resp, request_url, method="GET"):
        self.status_code = blast_resp.status
        self.url = str(blast_resp.url)
        self.text = blast_resp.body
        self.content = bytes(blast_resp.body_bytes)
        self.headers = CaseInsensitiveHeaders(blast_resp.headers)
        self.request = _RequestInfo(request_url, method)
        self.is_success = 200 <= blast_resp.status < 400
        self.elapsed_ms = blast_resp.elapsed_ms
        # Parse Set-Cookie headers into a simple dict (for r.cookies access)
        self.cookies = {}
        for k, v in blast_resp.headers:
            if k.lower() == "set-cookie":
                # Extract just the cookie name=value (before any ;)
                parts = v.split(";", 1)
                if "=" in parts[0]:
                    cname, cval = parts[0].split("=", 1)
                    self.cookies[cname.strip()] = cval.strip()

    @property
    def elapsed(self):
        """Return elapsed time as a timedelta .."""
        return _timedelta(milliseconds=self.elapsed_ms)

    def __bool__(self):
        return True

    def json(self, **kwargs):
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise BlasthttpHTTPError(
                f"HTTP {self.status_code} for url {self.url}",
                response=self,
            )

    def __str__(self):
        return self.text

    def __repr__(self):
        return f"BlasthttpResponse(status={self.status_code}, url='{self.url}')"


class BlasthttpHTTPError(Exception):
    """HTTP error raised by BlasthttpResponse.raise_for_status()."""

    def __init__(self, message, response=None):
        super().__init__(message)
        self.response = response
