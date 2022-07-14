import re
import html
import jwt as j

from .base import BaseInternalModule
from bbot.core.helpers.regexes import _email_regex


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
        web_spider_depth = self.excavate.scan.config.get("web_spider_depth", 0)
        if spider_danger and url_depth > web_spider_depth:
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
        "ASP.NET:5": r"at ([a-zA-Z0-9]*\.)*([a-zA-Z0-9]*)\([a-zA-Z0-9, ]*\)",
    }

    def report(self, result, name, event, **kwargs):
        self.excavate.debug(f"Found error message from parsing [{event.data.get('url')}] with regex [{name}]")
        self.excavate.emit_event(
            f"Error message Detected at [{event.data.get('url')}] Error Type: {name}", "FINDING", source=event
        )


class JWTExtractor(BaseExtractor):

    regexes = {"JWT": r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*"}

    def report(self, result, name, event, **kwargs):
        self.excavate.debug(f"Found JWT candidate [{result}]")
        try:
            j.decode(result, options={"verify_signature": False})
            jwt_headers = j.get_unverified_header(result)
            if jwt_headers["alg"].upper()[0:2] == "HS":
                self.excavate.emit_event(
                    f"JWT Identified [{result}] on [{event.data.get('url')}]", "FINDING", event, tags=["crackable"]
                )
            else:
                self.excavate.emit_event(f"JWT Identified [{result}] [{event.data.get('url')}]", "FINDING", event)

        except j.exceptions.DecodeError:
            self.excavate.debug(f"Error decoding JWT candidate {result}")


class excavate(BaseInternalModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]

    deps_pip = ["pyjwt"]

    def setup(self):

        self.url = URLExtractor(self)
        self.email = EmailExtractor(self)
        self.error = ErrorExtractor(self)
        self.jwt = JWTExtractor(self)

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
            self.search(body, [self.url, self.email, self.error, self.jwt], event, spider_danger=True)

            headers = event.data.get("response-header", "")
            self.search(headers, [self.url, self.email, self.error, self.jwt], event, spider_danger=False)

        else:

            self.search(str(data), [self.url, self.email, self.error, self.jwt], event)
