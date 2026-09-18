import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import quote as _urlquote

from bbot.errors import HttpCompareError

log = logging.getLogger("bbot.core.helpers.nowafpls")


DEFAULT_PADDING_SIZE = 1048576
DEFAULT_PAYLOAD = "<script>alert(1)</script>"
# Field name used to carry the junk padding in POST bodies. The double-underscore
# prefix keeps it out of the way of legitimate form fields when lightfuzz merges
# the pad into a real form.
PADDING_FIELD_NAME = "__nowafpls_pad"


@dataclass
class BypassResult:
    """
    Verdict from a nowafpls probe against a single host.

    `status` is one of the STATUS_* class constants. `bypassed` is a convenience
    boolean for the common "should I retry my probe with padding" question.
    """

    STATUS_NO_INTERFERENCE = "no_interference"
    STATUS_BYPASSED = "bypassed"
    STATUS_BLOCKED = "blocked"
    STATUS_ERROR = "error"

    status: str
    padding_size: int = DEFAULT_PADDING_SIZE
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

    A request the WAF kills outright (timeout / connection reset) counts as "differs",
    not as a match, so a dropped connection reads as interference rather than acceptance.

    Results are memoized per host for the scan's lifetime. Concurrent callers hit
    the same in-flight `asyncio.Task`, so exactly one probe runs per host.
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self._per_host: dict[str, asyncio.Task] = {}

    async def is_bypassable(
        self,
        event,
        padding_size: int = DEFAULT_PADDING_SIZE,
        payload: str = DEFAULT_PAYLOAD,
    ) -> BypassResult:
        """
        Probe the host and return a BypassResult. First caller runs the probe;
        concurrent callers await the same Task and get the cached verdict.
        """
        host = str(event.host)
        new_probe = host not in self._per_host
        if new_probe:
            self._per_host[host] = asyncio.create_task(self._probe(event, padding_size, payload))
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
        pad = f"{PADDING_FIELD_NAME}={'A' * DEFAULT_PADDING_SIZE}"
        return f"{pad}&{body}" if body else pad

    async def pad_json(self, event, data):
        """Prepend a junk padding key to a JSON dict body when the host's WAF is bypassable.
        No-op for events without a ``waf`` tag, non-bypassable hosts, or non-dict bodies."""
        if "waf" not in event.tags or not isinstance(data, dict):
            return data
        result = await self.is_bypassable(event)
        if not result.bypassed:
            return data
        return {PADDING_FIELD_NAME: "A" * DEFAULT_PADDING_SIZE, **data}

    async def _probe(self, event, padding_size: int, payload: str) -> BypassResult:
        url = event.url
        provider = self._identify_provider(event)
        log.debug(f"nowafpls: probing {url} with {padding_size} bytes of padding")
        encoded_payload = _urlquote(payload, safe="")
        benign_body = "q=hello"
        unpadded_body = f"q={encoded_payload}"
        padded_body = f"{PADDING_FIELD_NAME}={'A' * padding_size}&q={encoded_payload}"
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
                padding_size=padding_size,
                payload=payload,
                waf_provider=provider,
                error=f"could not baseline {url}: {e}",
            )

        if match_unpadded:
            return BypassResult(
                status=BypassResult.STATUS_NO_INTERFERENCE,
                padding_size=padding_size,
                payload=payload,
                waf_provider=provider,
            )

        try:
            match_padded, reasons_padded, *_ = await compare.compare(
                url, method="POST", data=padded_body, headers=headers, none_is_match=False
            )
        except HttpCompareError as e:
            return BypassResult(
                status=BypassResult.STATUS_ERROR,
                padding_size=padding_size,
                payload=payload,
                waf_provider=provider,
                error=f"padded compare failed for {url}: {e}",
                diff_reasons=list(reasons_unpadded),
            )

        if match_padded:
            return BypassResult(
                status=BypassResult.STATUS_BYPASSED,
                padding_size=padding_size,
                payload=payload,
                waf_provider=provider,
                diff_reasons=list(reasons_unpadded),
            )
        return BypassResult(
            status=BypassResult.STATUS_BLOCKED,
            padding_size=padding_size,
            payload=payload,
            waf_provider=provider,
            diff_reasons=list(reasons_padded),
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
