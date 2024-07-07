from bbot.core.helpers.regexes import url_regexes

from .base import BaseModule


class OAUTH(BaseModule):
    watched_events = ["DNS_NAME", "URL_UNVERIFIED"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "cloud-enum", "web-basic", "active", "safe"]
    meta = {
        "description": "Enumerate OAUTH and OpenID Connect services",
        "created_date": "2023-07-12",
        "author": "@TheTechromancer",
    }
    options = {"try_all": False}
    options_desc = {"try_all": "Check for OAUTH/IODC on every subdomain and URL."}

    in_scope_only = False
    scope_distance_modifier = 1
    _module_threads = 2

    async def setup(self):
        self.processed = set()
        self.regexes = list(url_regexes) + list(self.scan.dns_regexes)
        self.try_all = self.config.get("try_all", False)
        return True

    async def filter_event(self, event):
        if event.module == self or any(t in event.tags for t in ("target", "domain", "ms-auth-url")):
            return True
        elif self.try_all and event.scope_distance == 0:
            return True
        return False

    async def handle_event(self, event):
        _, domain = self.helpers.split_domain(event.data)
        source_domain = getattr(event, "source_domain", domain)
        if not self.scan.in_scope(source_domain):
            return

        oidc_tasks = []
        if event.scope_distance == 0:
            domain_hash = hash(domain)
            if domain_hash not in self.processed:
                self.processed.add(domain_hash)
                oidc_tasks.append(self.helpers.create_task(self.getoidc(f"https://login.windows.net/{domain}")))

        if event.type == "URL_UNVERIFIED":
            url = event.data
        else:
            url = f"https://{event.data}"

        oauth_tasks = []
        if self.try_all or any(t in event.tags for t in ("oauth-token-endpoint",)):
            oauth_tasks.append(self.helpers.create_task(self.getoauth(url)))
        if self.try_all or any(t in event.tags for t in ("ms-auth-url",)):
            for u in self.url_and_base(url):
                oidc_tasks.append(self.helpers.create_task(self.getoidc(u)))

        for oidc_task in oidc_tasks:
            url, token_endpoint, oidc_results = await oidc_task
            if token_endpoint:
                finding_event = self.make_event(
                    {
                        "description": f"OpenID Connect Endpoint (domain: {source_domain}) found at {url}",
                        "host": event.host,
                        "url": url,
                    },
                    "FINDING",
                    parent=event,
                )
                if finding_event:
                    finding_event.source_domain = source_domain
                    await self.emit_event(
                        finding_event,
                        context=f'{{module}} identified {{event.type}}: OpenID Connect Endpoint for "{source_domain}" at {url}',
                    )
                url_event = self.make_event(
                    token_endpoint, "URL_UNVERIFIED", parent=event, tags=["affiliate", "oauth-token-endpoint"]
                )
                if url_event:
                    url_event.source_domain = source_domain
                    await self.emit_event(
                        url_event,
                        context=f'{{module}} identified OpenID Connect Endpoint for "{source_domain}" at {{event.type}}: {url}',
                    )
            for result in oidc_results:
                if result not in (domain, event.data):
                    event_type = "URL_UNVERIFIED" if self.helpers.is_url(result) else "DNS_NAME"
                    await self.emit_event(
                        result,
                        event_type,
                        parent=event,
                        tags=["affiliate"],
                        context=f'{{module}} analyzed OpenID configuration for "{source_domain}" and found {{event.type}}: {{event.data}}',
                    )

        for oauth_task in oauth_tasks:
            url = await oauth_task
            if url:
                description = f"Potentially Sprayable OAUTH Endpoint (domain: {source_domain}) at {url}"
                oauth_finding = self.make_event(
                    {
                        "description": description,
                        "host": event.host,
                        "url": url,
                    },
                    "FINDING",
                    parent=event,
                )
                if oauth_finding:
                    oauth_finding.source_domain = source_domain
                    await self.emit_event(
                        oauth_finding,
                        context=f"{{module}} identified {{event.type}}: {description}",
                    )

    def url_and_base(self, url):
        yield url
        parsed = self.helpers.urlparse(url)
        baseurl = f"{parsed.scheme}://{parsed.netloc}/"
        if baseurl != url:
            yield baseurl

    async def getoidc(self, url):
        results = set()
        if not url.endswith("openid-configuration"):
            url = url.strip("/") + "/.well-known/openid-configuration"
        url_hash = hash("OIDC:" + url)
        token_endpoint = ""
        if url_hash not in self.processed:
            self.processed.add(url_hash)
            r = await self.helpers.request(url)
            if r is None:
                return url, token_endpoint, results
            try:
                json = r.json()
            except Exception:
                return url, token_endpoint, results
            if json and isinstance(json, dict):
                token_endpoint = json.get("token_endpoint", "")
                for found in await self.helpers.re.search_dict_values(json, *self.regexes):
                    results.add(found)
        results -= {token_endpoint}
        return url, token_endpoint, results

    async def getoauth(self, url):
        data = {
            "grant_type": "authorization_code",
            "client_id": "xxx",
            "redirect_uri": "https://example.com",
            "code": "xxx",
            "client_secret": "xxx",
        }
        url_hash = hash("OAUTH:" + url)
        if url_hash not in self.processed:
            self.processed.add(url_hash)
            r = await self.helpers.request(url, method="POST", data=data)
            if r is None:
                return
            if r.status_code in (400, 401):
                if "json" in r.headers.get("content-type", "").lower():
                    if any(x in r.text.lower() for x in ("invalid_grant", "invalid_client")):
                        return url
