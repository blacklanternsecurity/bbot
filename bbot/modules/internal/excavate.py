import re
import html
import base64
import jwt as j
from urllib.parse import urljoin

from bbot.core.helpers.regexes import _email_regex
from bbot.modules.internal.base import BaseInternalModule


class BaseExtractor:
    # If using capture groups, be sure to name them beginning with "capture".
    regexes = {}

    def __init__(self, excavate):
        self.excavate = excavate
        self.compiled_regexes = {}
        for rname, r in self.regexes.items():
            self.compiled_regexes[rname] = re.compile(r)

    async def search(self, content, event, **kwargs):
        results = set()
        async for result, name in self._search(content, event, **kwargs):
            results.add(result)
        for result in results:
            self.report(result, name, event, **kwargs)

    async def _search(self, content, event, **kwargs):
        for name, regex in self.compiled_regexes.items():
            # yield to event loop
            await self.excavate.helpers.sleep(0)
            for result in regex.findall(content):
                yield result, name

    def report(self, result, name, event):
        pass


class HostnameExtractor(BaseExtractor):
    regexes = {}

    def __init__(self, excavate):
        dns_targets = set(t.host for t in excavate.scan.target if t.host and isinstance(t.host, str))
        dns_whitelist = set(t.host for t in excavate.scan.whitelist if t.host and isinstance(t.host, str))
        dns_targets.update(dns_whitelist)
        dns_targets = sorted(dns_targets, key=len)
        dns_targets_set = set()
        for i, t in enumerate(dns_targets):
            if not any(x in dns_targets_set for x in excavate.helpers.domain_parents(t, include_self=True)):
                dns_targets_set.add(t)
                self.regexes[f"dns_name_{i+1}"] = r"((?:(?:[\w-]+)\.)+" + re.escape(t) + ")"
        super().__init__(excavate)

    def report(self, result, name, event, **kwargs):
        self.excavate.emit_event(result, "DNS_NAME", source=event)


class URLExtractor(BaseExtractor):
    regexes = {
        "fullurl": r"(?i)" + r"(\w{2,15})://((?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]+)*/?)",
        "a-tag": r"<a\s+(?:[^>]*?\s+)?href=([\"'])(.*?)\1",
        "script-tag": r"<script\s+(?:[^>]*?\s+)?src=([\"'])(.*?)\1",
    }

    prefix_blacklist = ["javascript:", "mailto:", "tel:", "data:", "vbscript:", "about:", "file:"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.web_spider_links_per_page = self.excavate.scan.config.get("web_spider_links_per_page", 20)

    async def search(self, content, event, **kwargs):
        result_hashes = set()
        results = []
        async for result in self._search(content, event, **kwargs):
            result_hash = hash(result)
            if result_hash not in result_hashes:
                result_hashes.add(result_hash)
                results.append(result)
        for i, (result, name) in enumerate(results):
            new_kwargs = dict(kwargs)
            if i > self.web_spider_links_per_page:
                # self.excavate.critical(f"SPIDER DANGER: {result}")
                new_kwargs["exceeded_max_links"] = True
            self.report(result, name, event, **new_kwargs)

    async def _search(self, content, event, **kwargs):
        parsed = getattr(event, "parsed", None)
        for name, regex in self.compiled_regexes.items():
            # yield to event loop
            await self.excavate.helpers.sleep(0)
            for result in regex.findall(content):
                if name == "fullurl":
                    protocol, other = result
                    result = f"{protocol}://{other}"

                elif name in ("a-tag", "script-tag") and parsed:
                    path = html.unescape(result[1])

                    for p in self.prefix_blacklist:
                        if path.lower().startswith(p.lower()):
                            self.excavate.debug(
                                f"omitted result from a-tag parser because of blacklisted prefix [{p}]"
                            )
                            continue

                    if not self.compiled_regexes["fullurl"].match(path):
                        source_url = event.parsed.geturl()
                        result = urljoin(source_url, path)
                        # this is necessary to weed out mailto: and such
                        if not self.compiled_regexes["fullurl"].match(result):
                            continue
                    else:
                        result = path

                yield result, name

    def report(self, result, name, event, **kwargs):
        consider_spider_danger = kwargs.get("consider_spider_danger", True)
        web_spider_distance = getattr(event, "web_spider_distance", 0)
        exceeded_max_links = kwargs.get("exceeded_max_links", False)

        tags = []

        parsed_uri = self.excavate.helpers.urlparse(result)
        host, port = self.excavate.helpers.split_host_port(parsed_uri.netloc)
        # Handle non-HTTP URIs (ftp, s3, etc.)
        if not "http" in parsed_uri.scheme.lower():
            event_data = {"host": str(host), "description": f"Non-HTTP URI: {result}"}
            parsed_url = getattr(event, "parsed", None)
            if parsed_url:
                event_data["url"] = parsed_url.geturl()
            self.excavate.emit_event(
                event_data,
                "FINDING",
                source=event,
            )
            self.excavate.emit_event(
                {"protocol": parsed_uri.scheme, "host": str(host)},
                "PROTOCOL",
                source=event,
            )
            return

        is_spider_danger = self.excavate.is_spider_danger(event, result)
        if (
            exceeded_max_links  # if we exceeded the max number of links
            or (consider_spider_danger and is_spider_danger)  # or if there's spider danger
            or (
                (not consider_spider_danger) and (web_spider_distance > self.excavate.max_redirects)
            )  # or if the spider distance is way out of control (greater than max_redirects)
        ):
            tags.append("spider-danger")

        self.excavate.debug(f"Found URL [{result}] from parsing [{event.data.get('url')}] with regex [{name}]")
        self.excavate.emit_event(result, "URL_UNVERIFIED", source=event, tags=tags)


class EmailExtractor(BaseExtractor):
    regexes = {"email": _email_regex}
    tld_blacklist = ["png", "jpg", "jpeg", "bmp", "ico", "gif", "svg", "css", "ttf", "woff", "woff2"]

    def report(self, result, name, event, **kwargs):
        result = result.lower()
        tld = result.split(".")[-1]
        if tld not in self.tld_blacklist:
            self.excavate.debug(f"Found email address [{result}] from parsing [{event.data.get('url')}]")
            self.excavate.emit_event(result, "EMAIL_ADDRESS", source=event)


class ErrorExtractor(BaseExtractor):
    regexes = {
        "PHP:1": r"\.php on line [0-9]+",
        "PHP:2": r"\.php</b> on line <b>[0-9]+",
        "PHP:3": "Fatal error:",
        "Microsoft SQL Server:1": r"\[(ODBC SQL Server Driver|SQL Server|ODBC Driver Manager)\]",
        "Microsoft SQL Server:2": "You have an error in your SQL syntax; check the manual",
        "Java:1": r"\.java:[0-9]+",
        "Java:2": r"\.java\((Inlined )?Compiled Code\)",
        "Perl": r"at (\/[A-Za-z0-9\.]+)*\.pm line [0-9]+",
        "Python": r"File \"[A-Za-z0-9\-_\./]*\", line [0-9]+, in",
        "Ruby": r"\.rb:[0-9]+:in",
        "ASP.NET:1": "Exception of type",
        "ASP.NET:2": "--- End of inner exception stack trace ---",
        "ASP.NET:3": "Microsoft OLE DB Provider",
        "ASP.NET:4": r"Error ([\d-]+) \([\dA-F]+\)",
    }

    def report(self, result, name, event, **kwargs):
        self.excavate.debug(f"Found error message from parsing [{event.data.get('url')}] with regex [{name}]")
        description = f"Error message Detected at Error Type: {name}"
        self.excavate.emit_event(
            {"host": str(event.host), "url": event.data.get("url", ""), "description": description},
            "FINDING",
            source=event,
        )


class JWTExtractor(BaseExtractor):
    regexes = {"JWT": r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*"}

    def report(self, result, name, event, **kwargs):
        self.excavate.debug(f"Found JWT candidate [{result}]")
        try:
            j.decode(result, options={"verify_signature": False})
            jwt_headers = j.get_unverified_header(result)
            tags = []
            if jwt_headers["alg"].upper()[0:2] == "HS":
                tags = ["crackable"]
            description = f"JWT Identified [{result}]"
            self.excavate.emit_event(
                {"host": str(event.host), "url": event.data.get("url", ""), "description": description},
                "FINDING",
                event,
                tags=tags,
            )

        except j.exceptions.DecodeError:
            self.excavate.debug(f"Error decoding JWT candidate {result}")


class SerializationExtractor(BaseExtractor):
    regexes = {"Java": r"(?:[^a-zA-Z0-9+/]|^)(rO0[a-zA-Z0-9+/]+={,2})"}

    def report(self, result, name, event, **kwargs):
        description = f"{name} serialized object found"
        self.excavate.emit_event(
            {"host": str(event.host), "url": event.data.get("url"), "description": description}, "FINDING", event
        )


class FunctionalityExtractor(BaseExtractor):
    regexes = {
        "File Upload Functionality": r"(<input[^>]+type=[\"']?file[\"']?[^>]+>)",
        "Web Service WSDL": r"(?i)((?:http|https)://[^\s]*?.(?:wsdl))",
    }

    def report(self, result, name, event, **kwargs):
        description = f"{name} found"
        self.excavate.emit_event(
            {"host": str(event.host), "url": event.data.get("url"), "description": description}, "FINDING", event
        )


class JavascriptExtractor(BaseExtractor):
    # based on on https://github.com/m4ll0k/SecretFinder/blob/master/SecretFinder.py

    regexes = {
        "google_api": r"AIza[0-9A-Za-z-_]{35}",
        "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
        "amazon_aws_access_key_id": r"A[SK]IA[0-9A-Z]{16}",
        "amazon_mws_auth_toke": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        # "amazon_aws_url": r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com",
        # "amazon_aws_url2": r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com",
        # "amazon_aws_url3": r"s3://[a-zA-Z0-9-\.\_]+",
        # "amazon_aws_url4": r"s3.amazonaws.com/[a-zA-Z0-9-\.\_]+",
        # "amazon_aws_url5": r"s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+",
        "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "authorization_basic": r"(?i)basic [a-zA-Z0-9:_\+\/-]{4,100}={0,2}",
        "authorization_bearer": r"bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}",
        "apikey": r"api(?:key|_key)\s?=\s?[\'\"\`][a-zA-Z0-9_\-]{5,100}[\'\"\`]",
        "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
        "paypal_braintree_access_token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "square_oauth_secret": r"sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
        "square_access_token": r"sqOatp-[0-9A-Za-z\-_]{22}",
        "stripe_standard_api": r"sk_live_[0-9a-zA-Z]{24}",
        "stripe_restricted_api": r"rk_live_[0-9a-zA-Z]{24}",
        "github_access_token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
        "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
        "ssh_dsa_private_key": r"-----BEGIN DSA PRIVATE KEY-----",
        "ssh_dc_private_key": r"-----BEGIN EC PRIVATE KEY-----",
        "pgp_private_block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "json_web_token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
        "slack_token": r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
        "SSH_privKey": r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
        "possible_creds_var": r"(?:password|passwd|pwd|pass)\s*=+\s*['\"][^\s'\"]{1,60}['\"]",
    }

    def report(self, result, name, event, **kwargs):
        # ensure that basic auth matches aren't false positives
        if name == "authorization_basic":
            try:
                b64test = base64.b64decode(result.split(" ", 1)[-1].encode())
                if b":" not in b64test:
                    return
            except (base64.binascii.Error, UnicodeDecodeError):
                return

        self.excavate.debug(f"Found Possible Secret in Javascript [{result}]")
        description = f"Possible secret in JS [{result}] Signature [{name}]"
        self.excavate.emit_event(
            {"host": str(event.host), "url": event.data.get("url", ""), "description": description}, "FINDING", event
        )


class excavate(BaseInternalModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive"]
    meta = {"description": "Passively extract juicy tidbits from scan data"}

    scope_distance_modifier = None

    async def setup(self):
        self.hostname = HostnameExtractor(self)
        self.url = URLExtractor(self)
        self.email = EmailExtractor(self)
        self.error_extractor = ErrorExtractor(self)
        self.jwt = JWTExtractor(self)
        self.javascript = JavascriptExtractor(self)
        self.serialization = SerializationExtractor(self)
        self.functionality = FunctionalityExtractor(self)
        self.max_redirects = self.scan.config.get("http_max_redirects", 5)

        return True

    async def search(self, source, extractors, event, **kwargs):
        for e in extractors:
            await e.search(source, event, **kwargs)

    async def handle_event(self, event):
        data = event.data

        # HTTP_RESPONSE is a special case
        if event.type == "HTTP_RESPONSE":
            # handle redirects
            web_spider_distance = getattr(event, "web_spider_distance", 0)
            num_redirects = max(getattr(event, "num_redirects", 0), web_spider_distance)
            location = event.data.get("location", "")
            host = event.host
            # if it's a redirect
            if location:
                # get the url scheme
                scheme = self.helpers.is_uri(location, return_scheme=True)
                # if there's no scheme (i.e. it's a relative redirect)
                if not scheme:
                    # then join the location with the current url
                    location = urljoin(event.parsed.geturl(), location)
                    scheme = self.helpers.is_uri(location, return_scheme=True)
                if scheme in ("http", "https"):
                    if num_redirects <= self.max_redirects:
                        url_event = self.make_event(location, "URL_UNVERIFIED", event)
                        if url_event is not None:
                            # inherit web spider distance from parent (don't increment)
                            source_web_spider_distance = getattr(event, "web_spider_distance", 0)
                            url_event.web_spider_distance = source_web_spider_distance
                            self.emit_event(url_event)
                    else:
                        self.verbose(f"Exceeded max HTTP redirects ({self.max_redirects}): {location}")
                elif scheme:
                    # we ran into a scheme that's not HTTP or HTTPS
                    data = {"host": host, "description": f"Non-standard URI scheme: {scheme}://", "url": location}
                    self.emit_event(data, "FINDING", event)

            body = self.helpers.recursive_decode(event.data.get("body", ""))
            # Cloud extractors
            self.helpers.cloud.excavate(event, body)
            await self.search(
                body,
                [
                    self.hostname,
                    self.url,
                    self.email,
                    self.error_extractor,
                    self.jwt,
                    self.javascript,
                    self.serialization,
                    self.functionality,
                ],
                event,
                consider_spider_danger=True,
            )

            headers = self.helpers.recursive_decode(event.data.get("raw_header", ""))
            await self.search(
                headers,
                [self.hostname, self.url, self.email, self.error_extractor, self.jwt, self.serialization],
                event,
                consider_spider_danger=False,
            )

        else:
            await self.search(
                str(data),
                [self.hostname, self.url, self.email, self.error_extractor, self.jwt, self.serialization],
                event,
            )
