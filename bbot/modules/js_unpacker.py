import json
import regex as re
from hashlib import md5, sha256
from urllib.parse import urljoin

import mmh3
import yara

from bbot.modules.base import BaseModule


class BaseUnpacker:
    name = "base"
    yara_rule = ""

    def __init__(self, module):
        self.module = module
        self.helpers = module.helpers

    async def unpack(self, event, match):
        raise NotImplementedError

    async def emit_unlocked(self, event, body):
        """Re-emit an HTTP_RESPONSE with unpacked body so excavate can extract from it."""
        data = dict(event.data)
        data["body"] = body
        # Distinct id from the original response so per-module dedup doesn't drop this.
        data["_reemit_source"] = "js_unpacker"
        # recompute body hashes so downstream content-dedup doesn't collapse this
        # against the original response
        body_bytes = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
        old_hash = data.get("hash") or {}
        data["hash"] = {
            **old_hash,
            "body_md5": md5(body_bytes).hexdigest(),
            "body_mmh3": mmh3.hash(body_bytes),
            "body_sha256": sha256(body_bytes).hexdigest(),
        }
        await self.module.emit_event(
            data,
            "HTTP_RESPONSE",
            parent=event.parent,
            tags=["js-unpacked"],
            context=f"{{module}} unpacked {self.name} JavaScript from {{event.type}}",
        )


class SourceMapUnpacker(BaseUnpacker):
    name = "source-map"
    yara_rule = """
rule source_map
{
    strings:
        $a = "sourceMappingURL="
    condition:
        any of them
}
"""
    _url_regex = re.compile(r"[/*][#@]\s*sourceMappingURL=(\S+)")

    async def unpack(self, event, match):
        body = event.body
        m = await self.helpers.re.search(self._url_regex, body)
        if not m:
            return
        map_ref = m.group(1)

        # data: URI
        if map_ref.startswith("data:"):
            parts = map_ref.split(",", 1)
            if len(parts) == 2:
                import base64

                try:
                    map_json = base64.b64decode(parts[1]).decode("utf-8", errors="replace")
                except Exception:
                    return
            else:
                return
        else:
            base_url = event.data.get("url", "")
            map_url = urljoin(base_url, map_ref)
            r = await self.helpers.request(map_url)
            if not r or r.status_code != 200:
                return
            map_json = r.text

        parsed = await self.helpers.run_in_executor_cpu(self._parse_source_map, map_json)
        if parsed is None:
            return
        num_sources, num_files, combined = parsed

        url = event.data.get("url", "unknown")
        source_url = map_url if not map_ref.startswith("data:") else url
        await self.module.emit_event(
            {
                "host": str(event.host),
                "url": source_url,
                "name": "Exposed source map",
                "description": f"Source map with {num_files} source files exposed ({num_sources} total entries)",
                "severity": "LOW",
                "confidence": "CONFIRMED",
            },
            "FINDING",
            parent=event,
            context="{module} discovered an exposed source map at {event.data[url]}",
        )
        await self.emit_unlocked(event, combined)

    @staticmethod
    def _parse_source_map(map_json):
        """Parse the map and join its embedded sources. CPU-bound; runs off the event loop."""
        try:
            source_map = json.loads(map_json)
        except (json.JSONDecodeError, ValueError):
            return None
        non_empty = [c for c in source_map.get("sourcesContent", []) if c and c.strip()]
        if not non_empty:
            return None
        return len(source_map.get("sources", [])), len(non_empty), "\n".join(non_empty)


class DeanEdwardsUnpacker(BaseUnpacker):
    name = "dean-edwards"
    yara_rule = """
rule dean_edwards_packer
{
    strings:
        $a = "eval(function(p,a,c,k,e,"
    condition:
        any of them
}
"""
    _extract_regex = re.compile(
        r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*\w\s*\)"
        r".*?\}\s*\(\s*'(.*?)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'(.*?)'\s*\.split\s*\(\s*'\|'\s*\)",
        re.DOTALL,
    )

    async def unpack(self, event, match):
        result = await self.helpers.run_in_executor_cpu(self._decode, event.body)
        if result:
            await self.emit_unlocked(event, result)

    @classmethod
    def _decode(cls, body):
        """Reverse the packer's base-N keyword substitution. CPU-bound; runs off the event loop."""
        m = cls._extract_regex.search(body)
        if not m:
            return ""

        payload, radix, count, keywords_str = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        keywords = keywords_str.split("|")

        def base_n(value, base):
            chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if value < base:
                return chars[value]
            return base_n(value // base, base) + chars[value % base]

        lookup = {}
        for i in range(count):
            key = base_n(i, radix)
            if i < len(keywords) and keywords[i]:
                lookup[key] = keywords[i]

        def replacer(m):
            word = m.group(0)
            return lookup.get(word, word)

        result = re.sub(r"\b\w+\b", replacer, payload)
        result = result.encode("utf-8").decode("unicode_escape", errors="replace")
        return result if result.strip() else ""


class ObfuscatorIOUnpacker(BaseUnpacker):
    name = "obfuscator-io"
    yara_rule = """
rule obfuscator_io
{
    strings:
        $a = /var _0x[a-f0-9]{4,6}\\s*=\\s*\\[/
    condition:
        any of them
}
"""
    _array_regex = re.compile(r"var\s+(_0x[a-f0-9]+)\s*=\s*\[(.*?)\];", re.DOTALL)

    async def unpack(self, event, match):
        result = await self.helpers.run_in_executor_cpu(self._deobfuscate, event.body)
        if result:
            await self.emit_unlocked(event, result)

    @classmethod
    def _deobfuscate(cls, body):
        """Inline the string-array lookups back into the source. CPU-bound; runs off the event loop."""
        arr_match = cls._array_regex.search(body)
        if not arr_match:
            return ""

        arr_name = arr_match.group(1)
        string_array = re.findall(r"'([^']*)'", arr_match.group(2))

        # find and apply rotation
        rot_pattern = (
            r"\(function\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{.*?push.*?shift.*?\}\s*\(\s*"
            + re.escape(arr_name)
            + r"\s*,\s*(0x[a-f0-9]+|\d+)\s*\)"
        )
        rot_match = re.search(rot_pattern, body, re.DOTALL)
        if rot_match:
            amount_str = rot_match.group(1)
            amount = int(amount_str, 16) if amount_str.startswith("0x") else int(amount_str)
            for _ in range(amount):
                string_array.append(string_array.pop(0))

        # find accessor function name
        accessor_pattern = (
            r"var\s+(_0x[a-f0-9]+)\s*=\s*function\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{"
            r"[^}]*" + re.escape(arr_name) + r"\s*\["
        )
        accessor_match = re.search(accessor_pattern, body)
        if not accessor_match:
            return ""

        accessor_name = accessor_match.group(1)

        def replace_accessor(m):
            idx_str = m.group(1)
            idx = int(idx_str, 16) if idx_str.startswith("0x") else int(idx_str)
            if 0 <= idx < len(string_array):
                return f"'{string_array[idx]}'"
            return m.group(0)

        result = re.sub(
            re.escape(accessor_name) + r"\(\s*'(0x[a-f0-9]+|\d+)'\s*\)",
            replace_accessor,
            body,
        )
        return result if result != body else ""


class NextJSUnpacker(BaseUnpacker):
    name = "nextjs"
    yara_rule = """
rule nextjs_manifest
{
    strings:
        $a = "self.__BUILD_MANIFEST"
        $b = "__NEXT_DATA__"
    condition:
        any of them
}
"""
    _nextdata_regex = re.compile(r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL)
    _route_regex = re.compile(r'"(/[^"]*)"')
    _chunk_regex = re.compile(r'"(static/chunks/[^"]*)"')

    async def unpack(self, event, match):
        body = event.body
        base_url = event.data.get("url", "")

        # __NEXT_DATA__ in HTML: extract buildId, emit _buildManifest.js URL
        nd_match = await self.helpers.re.search(self._nextdata_regex, body)
        if nd_match:
            try:
                next_data = json.loads(nd_match.group(1))
            except (json.JSONDecodeError, ValueError):
                return
            build_id = next_data.get("buildId")
            if build_id:
                manifest_path = f"/_next/static/{build_id}/_buildManifest.js"
                manifest_url = urljoin(base_url, manifest_path)
                await self.module.emit_event(
                    manifest_url,
                    "URL_UNVERIFIED",
                    parent=event,
                    tags=["js-unpacked"],
                    context="{module} extracted Next.js buildId and discovered {event.type}: {event.data}",
                )
            return

        # _buildManifest.js: extract routes and chunk paths
        if "self.__BUILD_MANIFEST" not in body:
            return

        routes = set(await self.helpers.re.findall(self._route_regex, body))
        chunks = set(await self.helpers.re.findall(self._chunk_regex, body))

        for route in routes:
            if route.startswith("/_") or route == "/":
                continue
            route_url = urljoin(base_url, route)
            await self.module.emit_event(
                route_url,
                "URL_UNVERIFIED",
                parent=event,
                tags=["js-unpacked"],
                context="{module} extracted Next.js route {event.type}: {event.data}",
            )

        for chunk in chunks:
            chunk_url = urljoin(base_url, f"/_next/{chunk}")
            await self.module.emit_event(
                chunk_url,
                "URL_UNVERIFIED",
                parent=event,
                tags=["js-unpacked"],
                context="{module} extracted Next.js chunk {event.type}: {event.data}",
            )


class WebpackUnpacker(BaseUnpacker):
    name = "webpack"
    yara_rule = """
rule webpack_bundle
{
    strings:
        $a = "webpackJsonp"
        $b = "webpackChunk"
        $c = "__webpack_require__"
    condition:
        any of them
}
"""
    _string_regex = re.compile(r"""(?:"([^"\\]{2,}(?:\\.[^"\\]*)*)"|'([^'\\]{2,}(?:\\.[^'\\]*)*)')""")
    _noise = frozenset({"use strict", "object", "function", "undefined", "string", "number", "boolean"})

    async def unpack(self, event, match):
        combined = await self.helpers.run_in_executor_cpu(self._extract_strings, event.body)
        if combined:
            await self.emit_unlocked(event, combined)

    @classmethod
    def _extract_strings(cls, body):
        """Flatten the bundle's string literals. CPU-bound; runs off the event loop."""
        strings = []
        for m in cls._string_regex.finditer(body):
            s = m.group(1) or m.group(2)
            if s and s not in cls._noise and not s.startswith("__"):
                strings.append(s)
        return "\n".join(strings)


class js_unpacker(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["HTTP_RESPONSE", "URL_UNVERIFIED", "FINDING"]
    flags = ["active", "safe", "web"]
    meta = {
        "description": "Detect and unpack JavaScript obfuscation/packing frameworks",
        "created_date": "2026-06-05",
        "author": "@liquidsec",
    }
    _module_threads = 4

    unpacker_classes = [
        SourceMapUnpacker,
        DeanEdwardsUnpacker,
        ObfuscatorIOUnpacker,
        NextJSUnpacker,
        WebpackUnpacker,
    ]

    async def setup(self):
        self.unpackers_by_rule = {}
        self.detections = []
        combined_rules = []
        for cls in self.unpacker_classes:
            unpacker = cls(self)
            rule_name = self._extract_rule_name(unpacker.yara_rule)
            self.unpackers_by_rule[rule_name] = unpacker
            combined_rules.append(unpacker.yara_rule)
        self.yara_rules = yara.compile(source="\n".join(combined_rules))
        return True

    @staticmethod
    def _extract_rule_name(yara_source):
        for line in yara_source.splitlines():
            line = line.strip()
            if line.startswith("rule "):
                return line.split()[1].rstrip("{").strip()
        raise ValueError(f"No rule name found in YARA source: {yara_source[:80]}")

    async def filter_event(self, event):
        if not event.body:
            return False, "no response body"
        content_type = event.data.get("content_type", "")
        if not any(t in content_type for t in ("javascript", "text/", "json", "xml")):
            return False, f"non-text content type: {content_type}"
        return True

    async def handle_event(self, event):
        body = event.body
        url = event.data.get("url", "unknown")
        matches = await self.helpers.run_in_executor_cpu(self.yara_rules.match, data=body)
        if not matches:
            return
        for match in matches:
            unpacker = self.unpackers_by_rule.get(match.rule)
            if unpacker is None:
                continue
            self.verbose(f"Detected {unpacker.name} in {url}")
            self.detections.append((unpacker.name, url))
            try:
                await unpacker.unpack(event, match)
            except Exception as e:
                self.warning(f"{unpacker.name} unpacker error on {url}: {e}")
