import re
import html
import jwt as j

from .base import BaseInternalModule
from bbot.core.helpers.regex import _email_regex

class BaseExtractor:
    regexes = {}

    def __init__(self, excavate):
        self.excavate = excavate
        self.compiled_regexes = {}
        for rname, r in self.regexes.items():
            self.compiled_regexes[rname] = re.compile(r)

    def search(self, content, event):
        for name, regex in self.compiled_regexes.items():
            results = regex.findall(content)
            for result in results:
                self.report(result, name, event)

    def report(self, result, name, event):
        pass


class URLExtractor(BaseExtractor):
    regexes = {
        "fullurl": r"https?://(?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]+)*/?",
        "a-tag": r"<a\s+(?:[^>]*?\s+)?href=([\"'])(.*?)\1",
    }

    prefix_blacklist = ['javascript:','mailto:']

    def report(self, result, name, event):

        tags = []
        parsed = getattr(event, "parsed", None)

        if name == "a-tag" and parsed:
            path = html.unescape(result[1]).lstrip("/")

            for p in prefix_blacklist:
                if path.startswith(p):
                    self.hugesuccess('omitted result from a-tag parser because of blacklisted prefix [{p}]')
                    return

            depth = len(path.strip("/").split("/"))
            result = f"{event.parsed.scheme}://{event.parsed.netloc}/{path}"

        if self.excavate.helpers.url_depth(result) > self.excavate.scan.config.get("web_spider_depth", 0):
            tags.append("spider-danger")

        self.excavate.debug(f"Found URL [{result}] from parsing [{event.data.get('url')}] with regex [{name}]")
        self.excavate.emit_event(result, "URL_UNVERIFIED", source=event, tags=tags)


class EmailExtractor(BaseExtractor):

    regexes = {"email":_email_regex}

    def report(self,result,name,event):
        self.excavate.debug(f"Found email address from parsing [{event.data.get('url')}]")
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

    def report(self, result, name, event):
        self.excavate.debug(f"Found error message from parsing [{event.data.get('url')}] with regex [{name}]")
        self.excavate.emit_event(
            f"Error message Detected at [{event.data.get('url')}] Error Type: {name}", "FINDING", source=event
        )


class JWTExtractor(BaseExtractor):

    regexes = {"JWT": r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*"}

    def report(self, result, name, event):
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
            self.debug(f"Error decoding JWT candidate {result}")


class excavate(BaseInternalModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]

    deps_pip = ["pyjwt"]

    def setup(self):

        self.extractors = [URLExtractor(self), ErrorExtractor(self), JWTExtractor(self)]
        return True

    def handle_event(self, event):

        data = event.data
        if event.type == "HTTP_RESPONSE":
            data = event.data.get("response-body", "")

        for extractor in self.extractors:
            extractor.search(data, event)
