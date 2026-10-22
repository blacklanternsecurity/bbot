import mimetypes
from contextlib import suppress

import puremagic

from .base import BaseAccessBypass, Probe

# appended to (suffix) or prepended before (prefix) the path
path_payloads = [
    "%09",
    "%20",
    "%23",
    "%2e",
    "%2f",
    ".",
    "?",
    ";",
    "..;",
    ";%09",
    ";%09..",
    ";%09..;",
    ";%2f..",
    "*",
    "/*",
    "..;/",
    ";/",
    "/..;/",
    "/;/",
    "/./",
    "//",
    "/.",
    "/?anything",
]

# extensions that make a request look like a static asset to edge/bot-management classifiers
static_extensions = [".ico", ".css", ".js", ".png", ".jpg", ".svg", ".woff2", ".gif", ".pdf"]
# extensions that may route the request to a different handler at the origin
routing_extensions = [".html", ".php", ".json"]


class path(BaseAccessBypass):
    friendly_name = "Path Manipulation"

    def probes(self):
        # two random sibling paths, so the catch-all control can baseline against the junk template
        sibling_mutations_1 = self.mutations(self.sibling_path(self.parsed_url.path))
        sibling_mutations_2 = self.mutations(self.sibling_path(self.parsed_url.path))
        seen = set()
        for key, mutated in self.mutations(self.parsed_url.path).items():
            if mutated in seen:
                continue
            seen.add(mutated)
            url = f"{self.base_url}{mutated}"
            sibling_1 = sibling_mutations_1.get(key)
            sibling_2 = sibling_mutations_2.get(key)
            yield Probe(
                key=key,
                label=f"Modified URL: GET {url}",
                url=url,
                sibling_url=f"{self.base_url}{sibling_1}" if sibling_1 else None,
                sibling_url_2=f"{self.base_url}{sibling_2}" if sibling_2 else None,
            )

    def sibling_path(self, path):
        """The same path with its last segment replaced by a random one."""
        segments = path.strip("/").split("/")
        segments[-1] = self.helpers.rand_string(8, digits=False)
        return "/" + "/".join(segments)

    @staticmethod
    def mutations(path):
        """{key: mutated path}. Keys are stable across paths with the same segment count."""
        stripped = path.strip("/")
        lstripped = path.lstrip("/")
        mutations = {
            "dot-prefix": f"/%2e/{lstripped}",
            # ASP.NET cookieless sessions
            "cookieless": f"/(S(X))/{stripped}",
            "cookieless-traversal": f"/(S(X))/../(S(X))/{stripped}",
        }
        for payload in path_payloads:
            mutations[f"suffix:{payload}"] = f"/{stripped}{payload}"
            # "?" only makes sense after the path
            if "?" not in payload:
                mutations[f"prefix:{payload}"] = f"/{payload}/{stripped}"

        segments = stripped.split("/") if stripped else []
        for i, segment in enumerate(segments):
            mutations[f"double-slash:{i}"] = "/" + "/".join(segments[:i] + ["/" + segment] + segments[i + 1 :])
            if segment[0].isalpha():
                swapped = segment[0].swapcase() + segment[1:]
                mutations[f"case-swap:{i}"] = "/" + "/".join(segments[:i] + [swapped] + segments[i + 1 :])
            mutations[f"semicolon:{i}"] = "/" + "/".join(segments[:i] + [f"{segment};x=.ico"] + segments[i + 1 :])
        mutations["semicolon-suffix"] = f"/{stripped};.css"

        for ext in static_extensions + routing_extensions:
            mutations[f"ext:{ext}"] = f"/{stripped}{ext}"
        return mutations

    async def confirm(self, probe, response):
        if probe.key.startswith("ext:"):
            ext = probe.key.split(":", 1)[1]
            if ext in static_extensions and self.is_real_asset(ext, response):
                self.access_bypass.debug(f"Rejecting {probe.label}: response is a real {ext} file")
                return False
        return True

    @staticmethod
    def is_real_asset(ext, response):
        """Whether the response is actually a file of type `ext`, by content type or by magic bytes."""
        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type and ext in mimetypes.guess_all_extensions(content_type):
            return True
        with suppress(puremagic.PureError, ValueError):
            if any(d.extension == ext for d in puremagic.magic_string(response.body_bytes or b"")):
                return True
        return False
