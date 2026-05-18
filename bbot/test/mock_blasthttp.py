"""
Bbot-specific test fixture that wraps `blasthttp.mock.BlasthttpMock`
with WebHelper kwarg translation.

The generic mock infrastructure — handler queue with FIFO + recycle,
URL/method/header/json predicates, sync + async callbacks — lives in
`blasthttp.mock`. This module adds the bbot-specific surface:

  - `handle_engine_request(self, web_helper, *args, **kwargs)`
    translates `WebHelper.request()` kwargs (auth tuple, cookies dict,
    json/data body, raise_error semantics, allow_redirects) into the
    blasthttp.request shape, dispatches through the mock, and returns
    the response (or an error dict the patched WebHelper translates
    into a WebError).

  - `handle_batch_stream(real_client, configs, concurrency, ...)`
    splits configs by `should_intercept`, dispatches mocked URLs
    through the handler queue and forwards the rest to `real_client`'s
    streaming batch API. The signature takes `real_client` per-call
    because the test fixture doesn't have one at construction time
    (the WebHelper's client is created later, when the scan starts).

`MockRequest`, `MockResponse`, `TimeoutException`, and the underlying
`BlasthttpMock` API (`add_response`, `add_callback`, `should_intercept`)
are all reachable directly so existing test imports
(``from bbot.test.mock_blasthttp import MockResponse``,
``module_test.blasthttp_mock.add_response(...)``) keep working.
"""

import json as _json
from urllib.parse import urlencode

from blasthttp.mock import (  # noqa: F401
    BlasthttpMock as _BlasthttpMock,
    MockRequest,
    MockResponse,
    TimeoutException,
)


class BlasthttpMock:
    """
    Bbot-flavored mock — wraps a `blasthttp.mock.BlasthttpMock` and
    adds bbot-specific WebHelper kwarg translation plus a per-call
    `real_client` batch-stream entry point. All other attributes
    (``add_response``, ``add_callback``, ``should_intercept``, etc.)
    forward to the inner mock via ``__getattr__``.
    """

    def __init__(self, should_mock_fn=None):
        self._inner = _BlasthttpMock(should_mock_fn=should_mock_fn)
        self._should_mock_fn = should_mock_fn

    # ── Forward everything else (add_response, add_callback,
    #    should_intercept, request, request_batch, ...) ──────────────
    def __getattr__(self, name):
        return getattr(self._inner, name)

    # ── Single-request entry point used by the patched WebHelper ────

    async def handle_engine_request(self, web_helper_self, *args, **kwargs):
        """
        Process kwargs the way ``WebHelper.request()`` does and dispatch
        through the mock. Called by the patched WebHelper.request.

        Pops bbot-/httpx-specific kwargs (``raise_error``, ``cache_for``,
        ``stream``, ``files``, ``client``), translates ``auth`` tuple
        and ``cookies`` dict into headers, assembles ``json``/``data``
        into a body, then dispatches via ``self._inner.request(...)``.
        """
        raise_error = kwargs.pop("raise_error", False)
        for k in ("cache_for", "client", "stream"):
            kwargs.pop(k, None)

        allow_redirects = kwargs.pop("allow_redirects", None)
        if allow_redirects is not None and "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = allow_redirects

        # Positional URL → kwarg.
        if len(args) == 1:
            kwargs["url"] = args[0]
            args = ()

        url = kwargs.pop("url", "")
        method = kwargs.pop("method", "GET")
        headers = kwargs.pop("headers", None) or {}
        body = kwargs.pop("body", None)
        data = kwargs.pop("data", None)
        files = kwargs.pop("files", None)
        json_body = kwargs.pop("json", None)
        body_sources = [
            name
            for name, val in (("body", body), ("data", data), ("json", json_body), ("files", files))
            if val is not None
        ]
        if len(body_sources) > 1:
            raise ValueError(
                f"request() got conflicting body kwargs {body_sources}; pass at most one of body, data, json, files"
            )
        cookies = kwargs.pop("cookies", None)
        auth = kwargs.pop("auth", None)
        # Drop kwargs that don't apply to mock dispatch but are valid on WebHelper.
        for k in ("timeout", "max_redirects", "proxy", "retries", "params", "max_body_size"):
            kwargs.pop(k, None)
        follow_redirects = kwargs.pop("follow_redirects", None)

        # Synthesize Authorization header from auth tuple (mirrors engine.py)
        if auth:
            import base64

            user, passwd = auth
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

        # Synthesize Cookie header from cookies dict (mirrors engine.py)
        if cookies:
            headers["Cookie"] = "; ".join(f"{ck}={cv}" for ck, cv in cookies.items())

        # Assemble body for handler-side matching/dispatch. files= wins (multipart),
        # then json, then data, then raw body.
        final_body = b""
        if files is None:
            if json_body is not None:
                final_body = _json.dumps(json_body)
                headers.setdefault("Content-Type", "application/json")
            elif data is not None:
                if isinstance(data, dict):
                    final_body = urlencode(data)
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                else:
                    final_body = data if isinstance(data, (bytes, bytearray)) else str(data)
            elif body is not None:
                final_body = body if isinstance(body, (bytes, bytearray)) else str(body)

        try:
            inner_kwargs = {
                "method": method,
                "headers": headers,
                "follow_redirects": follow_redirects,
            }
            if files is not None:
                inner_kwargs["files"] = files
            else:
                inner_kwargs["body"] = final_body
            return await self._inner.request(url, **inner_kwargs)
        except Exception as e:
            import logging

            logging.getLogger("bbot.test.mock").debug(f"Mock exception for {method} {url}: {e}")
            if raise_error:
                # Convert to the engine-style error dict that the patched
                # WebHelper.request expects to translate into a WebError.
                return {"_request_error": str(e), "_response": None}
            return None

    # ── Batch-streaming entry point (per-call real_client) ──────────

    async def handle_batch_stream(self, real_client, configs, concurrency, rate_limit=None):
        """
        Stream a batch of `BatchConfig` objects.

        Yields one ``BatchResult`` per item — mocked results first
        (input order, synchronous), then passthrough results
        (completion order from the real client).

        Takes ``real_client`` per-call because the WebHelper's client
        isn't available at fixture construction time. We can't pass
        it once at construction, so we manually split configs here
        and dispatch each side appropriately.
        """
        import blasthttp

        mock_configs = []
        passthrough_configs = []
        for config in configs:
            url = getattr(config, "url", str(config))
            if self._inner.should_intercept(url):
                mock_configs.append(config)
            else:
                passthrough_configs.append(config)

        # Dispatch mocked configs synchronously, in input order.
        for config in mock_configs:
            url = getattr(config, "url", str(config))
            method = getattr(config, "method", "GET") or "GET"
            raw_headers = getattr(config, "headers", None) or []
            headers = dict(raw_headers) if raw_headers else {}
            body = getattr(config, "body", None) or ""
            try:
                response = await self._inner.request(url, method=method, headers=headers, body=body)
                yield blasthttp.BatchResult(url, response=response)
            except Exception as e:
                yield blasthttp.BatchResult(url, error=str(e))

        # Stream passthrough through the real client. Its iterator
        # yields lists; flatten so the consumer sees one BatchResult
        # per yield (matches the mock's contract).
        if passthrough_configs:
            stream = real_client.request_batch_stream(
                passthrough_configs, concurrency=concurrency, rate_limit=rate_limit
            )
            async for item in stream:
                if isinstance(item, list):
                    for r in item:
                        yield r
                else:
                    yield item
