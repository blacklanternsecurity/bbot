from .base import BaseInternalModule
import re


class BaseExtractor:
    def __init__(self, content, parser, event):
        self.regex = ""
        self.content = content
        self.parser = parser
        self.event = event

    def search(self):
        results = re.findall(self.regex, self.content)
        for result in results:
            self.report(self.post_process(result))

    def report(self, result):
        pass

    def post_process(self, result):
        return result


class URLExtractor(BaseExtractor):
    def __init__(self, content, parser, event):
        BaseExtractor.__init__(self, content, parser, event)
        self.regex = r"https?://(?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]+)*/?"

    def report(self, result):
        self.parser.emit_event(result, "URL_UNVERIFIED", source=self.event, tags=["spider-danger"])


class parser(BaseInternalModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]

    def handle_event(self, event):
        # check for URLS
        extractor = URLExtractor(event.data.get("response-body", ""), self, event)
        extractor.search()
