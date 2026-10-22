from .base import BaseAccessBypass, Probe

# client-IP-spoofing headers; many WAFs / ext_authz filters trust these and skip enforcement
ip_headers = [
    "Client-IP",
    "X-Real-IP",
    "X-Client-IP",
    "X-Custom-IP-Authorization",
    "X-Forwarded-By",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Host",
    "X-True-IP",
    "X-Originating-IP",
    "Redirect",
    "Referer",
]
ip_values = ["127.0.0.1", "10.0.0.1"]


class headers(BaseAccessBypass):
    friendly_name = "Header Manipulation"

    def probes(self):
        path = self.parsed_url.path.lstrip("/")
        url = f"{self.base_url}/{path}"
        sibling = f"{self.base_url}/{self.helpers.rand_string(8, digits=False)}"
        sibling_2 = f"{self.base_url}/{self.helpers.rand_string(8, digits=False)}"

        for header in ip_headers:
            for value in ip_values:
                yield Probe(
                    key=f"{header}:{value}",
                    label=f"Added Header: {header}: {value}",
                    url=url,
                    headers={header: value},
                    sibling_url=sibling,
                    sibling_url_2=sibling_2,
                )
        yield Probe(
            key="xfport",
            label="Added Header: X-Forwarded-Port: 80",
            url=url,
            headers={"X-Forwarded-Port": "80"},
            sibling_url=sibling,
            sibling_url_2=sibling_2,
        )
        yield Probe(
            key="xoriginal",
            label=f"Added Header: X-Original-URL: /{path}",
            url=url,
            headers={"X-Original-URL": f"/{path}"},
        )
        yield Probe(
            key="xrewrite",
            label="Added Header: X-rewrite-url: nonsense",
            url=url,
            headers={"X-rewrite-url": "nonsense"},
        )
        yield Probe(
            key="cl0",
            label="Modified URL: POST (Content-Length: 0)",
            url=url,
            method="POST",
            headers={"Content-Length": "0"},
        )
        yield Probe(key="trace", label="Modified URL: TRACE", url=url, method="TRACE")
