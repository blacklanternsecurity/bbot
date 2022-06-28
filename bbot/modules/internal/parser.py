from .base import BaseInternalModule
import re


class BaseExtractor:
    regexes = {}

    def __init__(self, parser):
        self.parser = parser
        self.compiled_regexes = {}
        for rname, r in self.regexes.items():
            self.compiled_regexes[rname] = re.compile(r)

    def search(self, content, event):
        for name, regex in self.compiled_regexes.items():
            results = regex.findall(content)
            for result in results:
                self.report(self.post_process(result), name, event)

    def report(self, result, name, event):
        pass

    def post_process(self, result):
        return result


class URLExtractor(BaseExtractor):
    regexes = {"fullurl": r"https?://(?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]+)*/?"}

    def report(self, result, name, event):
        self.parser.debug(f"Found URL [{result}] from parsing [{event.data.get('url')}] with regex [{name}]")
        self.parser.emit_event(result, "URL_UNVERIFIED", source=event, tags=["spider-danger"])


class ErrorExtractor(BaseExtractor):

    regexes = {
        "PHP:1": r"\.php on line [0-9]+",
        "PHP:2": r"\.php</b> on line <b>[0-9]+",
        "PHP:3": "Fatal error:",
        "Microsoft SQL Server:1": r"\[(ODBC SQL Server Driver|SQL Server|ODBC Driver Manager)\]",
        "Microsoft SQL Server:2": "You have an error in your SQL syntax; check the manual",
    }

    def report(self, result, name, event):
        self.parser.debug(f"Found error message from parsing [{event.data.get('url')}] with regex [{name}]")
        self.parser.emit_event(
            f"Error message Detected at [{event.data.get('url')}] Error Type: {name}", "FINDING", source=event
        )


class parser(BaseInternalModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]

    def setup(self):

        self.url_extractor = URLExtractor(self)
        self.error_extractor = ErrorExtractor(self)
        return True

    def handle_event(self, event):

        response_data = event.data.get("response-body", "")

        # check for URLS
        self.url_extractor.search(response_data, event)
        # check for verbose error messages
        self.error_extractor.search(response_data, event)
