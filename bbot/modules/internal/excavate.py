import inspect
import asyncio
import yara
import regex as re
from bbot.modules.internal.base import BaseInternalModule


def find_subclasses(obj, base_class):
    subclasses = []
    for name, member in inspect.getmembers(obj):
        if inspect.isclass(member) and issubclass(member, base_class) and member is not base_class:
            subclasses.append(member)
    return subclasses


class ExcavateRule:

    yaraRules = {}
    context_description = "matching strings"

    def __init__(self, excavate):
        self.excavate = excavate
        self.helpers = excavate.helpers

    async def _callback(self, r, data, event, discovery_context):
        self.data = data
        self.event = event
        self.discovery_context = discovery_context
        await self.process(r)

    async def process(self, r):
        event_data = {
            "host": str(self.event.host),
            "url": self.event.data.get("url", ""),
            "description": r["meta"]["description"],
        }
        context = f"Found {self.context_description} in {self.discovery_context}"
        await self.report(event_data, context)

    async def report(self, event_data, context, event_type="FINDING"):
        await self.excavate.emit_event(
            event_data,
            event_type,
            parent=self.event,
            context=context,
        )

    async def regex_search(self, content, regex):
        self.excavate.hugeinfo(regex)
        await self.excavate.helpers.sleep(0)
        for result in await self.helpers.re.findall(regex, content):
            yield result


class excavate(BaseInternalModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive"]
    meta = {
        "description": "Passively extract juicy tidbits from scan data",
        "created_date": "2022-06-27",
        "author": "@liquidsec",
    }

    options = {"recursive_decode": False}
    options_desc = {
        "recursive_decode": "Recursively URL-decode responses before processing",
    }
    scope_distance_modifier = None

    class excavateTestRule(ExcavateRule):
        yaraRules = {
            "SearchForText": 'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
            "SearchForText2": 'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text = "DDDDEEEEFFFF" condition: $text }',
        }

    class HostnameExtractor(ExcavateRule):
        yaraRules = {}

        def __init__(self, excavate):
            regexes_component_list = []
            for i, r in enumerate(excavate.scan.dns_regexes):
                regexes_component_list.append(rf"$dns_name_{i} = /\b{r.pattern}/ nocase")
            regexes_component = " ".join(regexes_component_list)
            self.yaraRules[f"hostname_extraction"] = (
                rf'rule hostname_extraction {{meta: description = "Matches DNS hostname pattern" strings: {regexes_component} condition: any of them}}'
            )
            super().__init__(excavate)
            excavate.critical(self.yaraRules)

        async def process(self, r):

            if r["matches"]:
                for h in r["strings"]:
                    self.excavate.critical(h)
                    self.excavate.critical(h.identifier)
                    self.excavate.critical(h.instances)
                    hostname_regex = re.compile(
                        self.excavate.scan.dns_regexes[int(h.identifier.split("_")[-1])].pattern
                    )
                    results = set(h.instances)
                    for result in results:
                        context = f"excavate's hostname extractor found DNS_NAME: {result} from  using regex derived from target domain"
                        await self.report(result, context, event_type="DNS_NAME")

    async def setup(self):
        self.recursive_decode = self.config.get("recursive_decode", False)
        max_redirects = self.scan.config.get("http_max_redirects", 5)
        self.web_spider_distance = self.scan.config.get("web_spider_distance", 0)
        self.max_redirects = max(max_redirects, self.web_spider_distance)
        self.yaraRulesDict = {}
        self.yaraCallbackDict = {}

        for module in self.scan.modules.values():
            if not str(module).startswith("_"):
                ExcavateRules = find_subclasses(module, ExcavateRule)
                for e in ExcavateRules:
                    excavateRule = e(self)
                    for ruleName, ruleContent in excavateRule.yaraRules.items():
                        self.yaraRulesDict[ruleName] = ruleContent
                        self.yaraCallbackDict[ruleName] = excavateRule._callback

        self.yaraRules = yara.compile(source="\n".join(self.yaraRulesDict.values()))
        return True

    async def match_callback(self, result, data, event, discovery_context):
        if result["matches"]:
            rule_name = result["rule"]
            if rule_name in self.yaraCallbackDict.keys():
                await self.yaraCallbackDict[rule_name](result, data, event, discovery_context)

    async def search(self, data, event, discovery_context="HTTP response"):
        self.yaraRules.match(
            data=data,
            callback=lambda result: asyncio.create_task(self.match_callback(result, data, event, discovery_context)),
        )

    async def handle_event(self, event):
        data = event.data
        # handle redirects
        web_spider_distance = getattr(event, "web_spider_distance", 0)
        num_redirects = max(getattr(event, "num_redirects", 0), web_spider_distance)
        location = getattr(event, "redirect_location", "")
        # if it's a redirect
        if location:
            # get the url scheme
            scheme = self.helpers.is_uri(location, return_scheme=True)
            if scheme in ("http", "https"):
                if num_redirects <= self.max_redirects:
                    # tag redirects to out-of-scope hosts as affiliates
                    url_event = self.make_event(location, "URL_UNVERIFIED", event, tags="affiliate")
                    if url_event is not None:
                        # inherit web spider distance from parent (don't increment)
                        parent_web_spider_distance = getattr(event, "web_spider_distance", 0)
                        url_event.web_spider_distance = parent_web_spider_distance
                        await self.emit_event(
                            url_event,
                            context='{module} looked in "Location" header and found {event.type}: {event.data}',
                        )
                else:
                    self.verbose(f"Exceeded max HTTP redirects ({self.max_redirects}): {location}")

        body = event.data.get("body", "")
        headers = event.data.get("raw_header", "")
        if body == "" and headers == "":
            return
        if self.recursive_decode:
            body = await self.helpers.re.recursive_decode(body)
            headers = await self.helpers.re.recursive_decode(headers)

        await self.search(
            body,
            event,
            #  consider_spider_danger=True,
            discovery_context="HTTP response (body)",
        )

        await self.search(
            headers,
            event,
            #  consider_spider_danger=True,
            discovery_context="HTTP response (headers)",
        )
