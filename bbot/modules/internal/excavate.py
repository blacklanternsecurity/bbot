import re
import html
import base64
import jwt as j

from bbot.core.helpers.regexes import _email_regex
from bbot.modules.internal.base import BaseInternalModule


class BaseExtractor:
    regexes = {}

    def __init__(self, excavate):
        self.excavate = excavate
        self.compiled_regexes = {}
        for rname, r in self.regexes.items():
            self.compiled_regexes[rname] = re.compile(r)

    def search(self, content, event, **kwargs):
        for name, regex in self.compiled_regexes.items():
            results = regex.findall(content)
            for result in results:
                self.report(result, name, event, **kwargs)

    def report(self, result, name, event):
        pass


class HostnameExtractor(BaseExtractor):
    regexes = {}

    def __init__(self, excavate):
        dns_targets = [t for t in excavate.scan.target if t.type == "DNS_NAME"]
        for i, t in enumerate(dns_targets):
            self.regexes[f"dns_name_{i+1}"] = r"(?:(?:[\w-]+)\.)+" + str(t.host)
        super().__init__(excavate)

    def report(self, result, name, event, **kwargs):
        self.excavate.emit_event(result, "DNS_NAME", source=event)


class URLExtractor(BaseExtractor):
    regexes = {
        "fullurl": r"https?://(?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]+)*/?",
        "a-tag": r"<a\s+(?:[^>]*?\s+)?href=([\"'])(.*?)\1",
        "script-tag": r"<script\s+(?:[^>]*?\s+)?src=([\"'])(.*?)\1",
    }

    prefix_blacklist = ["javascript:", "mailto:", "tel:"]

    def report(self, result, name, event, **kwargs):

        spider_danger = kwargs.get("spider_danger", True)

        tags = []
        parsed = getattr(event, "parsed", None)

        if (name == "a-tag" or name == "script-tag") and parsed:
            path = html.unescape(result[1]).lstrip("/")
            if not path.startswith("http://") and not path.startswith("https://"):
                result = f"{event.parsed.scheme}://{event.parsed.netloc}/{path}"
            else:
                result = path

            for p in self.prefix_blacklist:
                if path.startswith(p):
                    self.excavate.debug(f"omitted result from a-tag parser because of blacklisted prefix [{p}]")
                    return

        url_depth = self.excavate.helpers.url_depth(result)
        web_spider_depth = self.excavate.scan.config.get("web_spider_depth", 1)
        spider_distance = getattr(event, "web_spider_distance", 0)
        web_spider_distance = self.excavate.scan.config.get("web_spider_distance", 0)
        if spider_danger and (url_depth > web_spider_depth or spider_distance > web_spider_distance):
            tags.append("spider-danger")

        self.excavate.debug(f"Found URL [{result}] from parsing [{event.data.get('url')}] with regex [{name}]")
        self.excavate.emit_event(result, "URL_UNVERIFIED", source=event, tags=tags)


class EmailExtractor(BaseExtractor):

    regexes = {"email": _email_regex}

    def report(self, result, name, event, **kwargs):
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


class JavascriptExtractor(BaseExtractor):
    # based on on https://github.com/m4ll0k/SecretFinder/blob/master/SecretFinder.py

    regexes = {
        "google_api": r"AIza[0-9A-Za-z-_]{35}",
        "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
        "amazon_aws_access_key_id": r"A[SK]IA[0-9A-Z]{16}",
        "amazon_mws_auth_toke": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "amazon_aws_url": r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com",
        "amazon_aws_url2": r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com",
        "amazon_aws_url3": r"s3://[a-zA-Z0-9-\.\_]+",
        "amazon_aws_url4": r"s3.amazonaws.com/[a-zA-Z0-9-\.\_]+",
        "amazon_aws_url5": r"s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+",
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
                b64test = base64.b64decode(result.split(" ")[1].encode())
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

    deps_pip = ["pyjwt"]

    def setup(self):

        self.hostname = HostnameExtractor(self)
        self.url = URLExtractor(self)
        self.email = EmailExtractor(self)
        self.error = ErrorExtractor(self)
        self.jwt = JWTExtractor(self)
        self.javascript = JavascriptExtractor(self)
        self.serialization = SerializationExtractor(self)

        return True

    def search(self, source, extractors, event, **kwargs):
        for e in extractors:
            e.search(source, event, **kwargs)

    def handle_event(self, event):

        data = event.data

        # HTTP_RESPONSE is a special case
        if event.type == "HTTP_RESPONSE":

            # handle redirects
            location = event.data.get("location", "")
            if location:
                if not location.lower().startswith("http"):
                    location = event.parsed._replace(path=location).geturl()
                self.emit_event(location, "URL_UNVERIFIED", event)

            body = event.data.get("response-body", "")
            self.search(
                body,
                [self.hostname, self.url, self.email, self.error, self.jwt, self.javascript, self.serialization],
                event,
                spider_danger=True,
            )

            headers = event.data.get("response-header", "")
            self.search(
                headers,
                [self.hostname, self.url, self.email, self.error, self.jwt, self.serialization],
                event,
                spider_danger=False,
            )

        else:

            self.search(
                str(data), [self.hostname, self.url, self.email, self.error, self.jwt, self.serialization], event
            )
