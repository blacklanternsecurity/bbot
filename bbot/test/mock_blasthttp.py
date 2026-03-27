"""
Mock fixture for blasthttp web requests.

Intercepts WebHelper.request() at the Python level. Requests to external
hosts are handled by registered mock responses/callbacks. Requests to
localhost/127.0.0.1 pass through to the real blasthttp client.

Drop-in types (MockRequest, MockResponse, TimeoutException) replace their
equivalents in test callback signatures.
"""

import re
import json as _json
import asyncio
from urllib.parse import urlparse, urlencode

from bbot.core.helpers.web.blast_response import BlasthttpResponse


# ── Mock types for test callbacks ────


class TimeoutException(RuntimeError):
    """Mock timeout exception for tests."""

    pass


class MockRequest:
    """Mock request object for test callbacks."""

    def __init__(self, url, method="GET", headers=None, content=b""):
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.content = content if isinstance(content, bytes) else content.encode()


class MockResponse:
    """Mock response object for test callbacks."""

    def __init__(self, status_code=200, json=None, text=None, headers=None):
        self.status_code = status_code
        if text is not None:
            self.text = text
        elif json is not None:
            self.text = _json.dumps(json)
        else:
            self.text = ""
        self.headers = headers or {}


# ── Internal mock helpers ──────────────────────────────────────────


class _MockRawResponse:
    """Mimics blasthttp PyO3 Response for BlasthttpResponse.__init__."""

    def __init__(self, status=200, url="", body="", headers=None, elapsed_ms=0):
        self.status = status
        self.url = url
        self.body = body
        self.body_bytes = body.encode("utf-8", errors="surrogateescape") if isinstance(body, str) else body
        self.headers = headers or []
        self.elapsed_ms = elapsed_ms


# ── Main mock class ───────────────────────────────────────────────


class BlasthttpMock:
    """
    Mock fixture that intercepts HTTPEngine.request() calls.

    Supports the add_response() / add_callback() API for mocking HTTP requests in
    tests.
    """

    def __init__(self, should_mock_fn=None):
        self._handlers = []  # FIFO queue of handlers
        self._recycled = []  # consumed handlers available for reuse
        self._should_mock = should_mock_fn or (lambda host: True)

    def add_response(
        self,
        url=None,
        method=None,
        text=None,
        json=None,
        content=None,
        status_code=200,
        headers=None,
        match_headers=None,
        match_json=None,
    ):
        """Register a static mock response."""
        # Normalize response headers to list of tuples
        if headers is None:
            header_list = []
        elif isinstance(headers, dict):
            header_list = []
            for k, v in headers.items():
                if isinstance(v, list):
                    # Expand list values into multiple tuples (e.g. multiple Set-Cookie)
                    for item in v:
                        header_list.append((k, item))
                else:
                    header_list.append((k, v))
        elif isinstance(headers, list):
            header_list = list(headers)
        else:
            header_list = []

        # Build body — content (bytes) takes lowest priority after text/json
        if text is not None:
            body = text
            # Auto-add Content-Type for text
            if not any(k.lower() == "content-type" for k, _ in header_list):
                header_list.append(("Content-Type", "text/plain; charset=utf-8"))
        elif json is not None:
            body = _json.dumps(json)
            if not any(k.lower() == "content-type" for k, _ in header_list):
                header_list.append(("Content-Type", "application/json"))
        elif content is not None:
            # Raw bytes content — decode to str for body field, keep as-is for body_bytes
            if isinstance(content, bytes):
                body = content.decode("utf-8", errors="surrogateescape")
            else:
                body = str(content)
            if not any(k.lower() == "content-type" for k, _ in header_list):
                header_list.append(("Content-Type", "application/octet-stream"))
        else:
            body = ""

        self._handlers.append(
            {
                "type": "response",
                "url": url,
                "method": method,
                "match_headers": match_headers,
                "match_json": match_json,
                "status_code": status_code,
                "body": body,
                "headers": header_list,
            }
        )

    def add_callback(self, callback, url=None):
        """Register a callback that receives MockRequest and returns MockResponse."""
        self._handlers.append(
            {
                "type": "callback",
                "url": url,
                "callback": callback,
            }
        )

    def should_intercept(self, url):
        """Check if this URL should be intercepted by the mock."""
        host = urlparse(url).hostname or ""
        return self._should_mock(host)

    def _url_matches(self, pattern, url):
        """Match URL against string or compiled regex."""
        if pattern is None:
            return True
        if isinstance(pattern, re.Pattern):
            return pattern.search(url) is not None
        return url == pattern

    def _matches(self, handler, url, method, headers, body_str):
        """Check if a handler matches the request criteria."""
        if not self._url_matches(handler.get("url"), url):
            return False

        handler_method = handler.get("method")
        if handler_method and method.upper() != handler_method.upper():
            return False

        match_headers = handler.get("match_headers")
        if match_headers:
            for k, v in match_headers.items():
                if headers.get(k) != v:
                    return False

        match_json = handler.get("match_json")
        if match_json is not None:
            try:
                req_json = _json.loads(body_str) if body_str else {}
                for k, v in match_json.items():
                    if req_json.get(k) != v:
                        return False
            except (ValueError, TypeError):
                return False

        return True

    def _make_blast_response(self, url, method, status_code, body, headers):
        """Create a BlasthttpResponse from mock data."""
        raw = _MockRawResponse(
            status=status_code,
            url=url,
            body=body,
            headers=headers,
        )
        return BlasthttpResponse(raw, request_url=url, method=method)

    async def _find_and_execute(self, url, method, headers, body_str):
        """
        Find a matching handler and execute it.

        Handlers are consumed in FIFO order.
        Consumed handlers are recycled so they can be reused for subsequent
        requests (matching can_send_already_matched_responses=True).
        """
        # Try primary handlers first, then recycled ones
        for handler_list in (self._handlers, self._recycled):
            for i, handler in enumerate(handler_list):
                if handler["type"] == "response":
                    if self._matches(handler, url, method, headers, body_str):
                        # Consume from primary queue, recycle
                        if handler_list is self._handlers:
                            self._handlers.pop(i)
                            self._recycled.append(handler)
                        return self._make_blast_response(
                            url, method, handler["status_code"], handler["body"], handler["headers"]
                        )

                elif handler["type"] == "callback":
                    if handler.get("url") is not None and not self._url_matches(handler["url"], url):
                        continue

                    # Consume from primary queue, recycle
                    if handler_list is self._handlers:
                        self._handlers.pop(i)
                        self._recycled.append(handler)

                    callback = handler["callback"]
                    content = body_str.encode() if isinstance(body_str, str) else (body_str or b"")
                    mock_request = MockRequest(url=url, method=method, headers=headers, content=content)

                    # Call callback — may be sync or async, may raise
                    if asyncio.iscoroutinefunction(callback):
                        result = await callback(mock_request)
                    else:
                        result = callback(mock_request)

                    # Convert MockResponse to BlasthttpResponse
                    if isinstance(result, MockResponse):
                        if isinstance(result.headers, dict):
                            resp_headers = []
                            for k, v in result.headers.items():
                                if isinstance(v, list):
                                    for item in v:
                                        resp_headers.append((k, item))
                                else:
                                    resp_headers.append((k, v))
                        else:
                            resp_headers = result.headers or []
                        return self._make_blast_response(url, method, result.status_code, result.text, resp_headers)

                    return result

        # No handler matched — raise error (simulates unreachable host)
        raise RuntimeError(f"No mock response registered for {method} {url}")

    async def handle_engine_request(self, web_helper_self, *args, **kwargs):
        """
        Process kwargs like WebHelper.request() and return a mock response.

        Called by the patched request method when should_intercept() is True.
        """
        raise_error = kwargs.pop("raise_error", False)
        kwargs.pop("cache_for", None)
        kwargs.pop("client", None)
        kwargs.pop("stream", None)
        kwargs.pop("files", None)

        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        if len(args) == 1:
            kwargs["url"] = args[0]
            args = ()

        url = kwargs.pop("url", "")
        method = kwargs.pop("method", "GET")
        headers = kwargs.pop("headers", None) or {}
        body = kwargs.pop("body", None)
        data = kwargs.pop("data", None)
        json_body = kwargs.pop("json", None)
        # Pop remaining kwargs so they don't cause issues
        cookies = kwargs.pop("cookies", None)
        auth = kwargs.pop("auth", None)
        kwargs.pop("timeout", None)
        follow_redirects = kwargs.pop("follow_redirects", None)
        kwargs.pop("max_redirects", None)
        kwargs.pop("proxy", None)
        kwargs.pop("retries", None)
        kwargs.pop("params", None)
        kwargs.pop("max_body_size", None)

        # Synthesize Authorization header from auth tuple (mirrors engine.py)
        if auth:
            import base64

            user, passwd = auth
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

        # Synthesize Cookie header from cookies dict (mirrors engine.py)
        if cookies:
            cookie_str = "; ".join(f"{ck}={cv}" for ck, cv in cookies.items())
            headers["Cookie"] = cookie_str

        # Determine body string for matching
        body_str = ""
        if json_body is not None:
            body_str = _json.dumps(json_body)
        elif data is not None:
            if isinstance(data, dict):
                body_str = urlencode(data)
            else:
                body_str = str(data)
        elif body is not None:
            body_str = str(body)

        try:
            response = await self._find_and_execute(url, method, headers, body_str)

            # Follow redirects if requested (mirrors blasthttp behavior)
            max_hops = 10
            while follow_redirects and response is not None and max_hops > 0:
                if not hasattr(response, "status_code"):
                    break
                if response.status_code not in (301, 302, 303, 307, 308):
                    break
                location = response.headers.get("location", "")
                if not location:
                    break
                # Resolve relative redirect URLs
                if location.startswith("/"):
                    parsed_url = urlparse(url)
                    location = f"{parsed_url.scheme}://{parsed_url.netloc}{location}"
                url = location
                max_hops -= 1
                response = await self._find_and_execute(url, method, headers, body_str)

            return response
        except Exception as e:
            import logging

            logging.getLogger("bbot.test.mock").debug(f"Mock exception for {method} {url}: {e}")
            error_msg = str(e)
            if raise_error:
                return {"_request_error": error_msg, "_response": None}
            return None
