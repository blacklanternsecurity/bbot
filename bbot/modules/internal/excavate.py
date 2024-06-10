import inspect
import asyncio
import yara
import regex as re
from bbot.errors import ExcavateError
import bbot.core.helpers.regexes as bbot_regexes
from bbot.modules.internal.base import BaseInternalModule
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse


def find_subclasses(obj, base_class):
    subclasses = []
    for name, member in inspect.getmembers(obj):
        if inspect.isclass(member) and issubclass(member, base_class) and member is not base_class:
            subclasses.append(member)
    return subclasses


def _exclude_key(original_dict, key_to_exclude):
    return {key: value for key, value in original_dict.items() if key != key_to_exclude}


def extract_params_location(location_header_value, original_parsed_url):
    """
    Extracts parameters from a location header, yielding them one at a time.

    Args:
        location_header_value (dict): Contents of location header
        original_url: The original parsed URL the header was received from (urllib.parse.ParseResult)

    Yields:
        method(str), parsed_url(urllib.parse.ParseResult), parameter_name(str), original_value(str), regex_name(str), additional_params(dict): The HTTP method associated with the parameter (GET, POST, None), A urllib.parse.ParseResult object representing the endpoint associated with the parameter, the parameter found in the location header, its original value (if available), the name of the detecting regex, a dict of additional params if any
    """

    if location_header_value.startswith("http://") or location_header_value.startswith("https://"):
        parsed_url = urlparse(location_header_value)
    else:
        parsed_url = urlparse(f"{original_parsed_url.scheme}://{original_parsed_url.netloc}{location_header_value}")

    params = parse_qs(parsed_url.query)
    flat_params = {k: v[0] for k, v in params.items()}

    for p, p_value in flat_params.items():
        log.debug(f"FOUND PARAM ({p}) IN LOCATION HEADER")
        yield "GET", parsed_url, p, p_value, "location_header", _exclude_key(flat_params, p)


class ExcavateRule:
    """
    The BBOT Regex Commandments:

    1) Thou shalt employ YARA regexes in place of Python regexes, save when necessity doth compel otherwise.
    2) Thou shalt ne'er wield a Python regex against a vast expanse of text.
    3) Whensoever it be possible, thou shalt favor string matching o'er regexes.

    Amen.
    """

    yaraRules = {}
    context_description = "matching strings"

    def __init__(self, excavate):
        self.excavate = excavate
        self.helpers = excavate.helpers

    async def _callback(self, r, data, event, assigned_cookies, discovery_context):
        self.data = data
        self.event = event
        self.assigned_cookies = assigned_cookies
        self.discovery_context = discovery_context
        await self.process(r)

    async def process(self, r):
        event_data = {
            "host": str(self.event.host),
            "url": self.event.data.get("url", ""),
            "description": r.meta["description"],
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
        await self.excavate.helpers.sleep(0)
        for result in await self.helpers.re.findall(regex, content):
            yield result


class excavate(BaseInternalModule):
    """
    Example (simple) Excavate Rules:

    class excavateTestRule(ExcavateRule):
        yaraRules = {
            "SearchForText": 'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
            "SearchForText2": 'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
        }
    """

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["passive"]
    meta = {
        "description": "Passively extract juicy tidbits from scan data",
        "created_date": "2022-06-27",
        "author": "@liquidsec",
    }

    options = {
        "recursive_decode": False,
        "retain_querystring": False,
    }
    options_desc = {
        "recursive_decode": "Recursively URL-decode responses before processing",
        "retain_querystring": "Keep the querystring intact on emitted WEB_PARAMETERS",
    }
    scope_distance_modifier = None

    class ParameterExtractor(ExcavateRule):

        yaraRules = {
            "params_getform": r'rule params_getform { meta: description = "Contains an GET form" strings: $getform_regex = /<form[^>]*\bmethod=["\']?get["\']?[^>]*>.*<\/form>/s nocase condition: $getform_regex}'
        }
        yaraRules = {}

        parameter_blacklist = [
            "__VIEWSTATE",
            "__EVENTARGUMENT",
            "__EVENTVALIDATION",
            "__EVENTTARGET",
            "__EVENTARGUMENT",
            "__VIEWSTATEGENERATOR",
            "__SCROLLPOSITIONY",
            "__SCROLLPOSITIONX",
            "ASP.NET_SessionId",
            "JSESSIONID",
            "PHPSESSID",
        ]

        class ParameterExtractorRule:
            name = ""
            yaraRules = {}

            def extract(self):
                pass

            def __init__(self, excavate, result):
                self.excavate = excavate
                self.result = result

        class GetForm(ParameterExtractorRule):

            name = "get_form"
            extraction_regex = r'/<form[^>]*\bmethod=["\']?get["\']?[^>]*>.*<\/form>/s nocase'

            def extract(self):
                get_forms = bbot_regexes.get_form_regex.findall(str(self.result))
                for form_action, form_content in get_forms:
                    form_parameters = {}
                    input_tags = bbot_regexes.input_tag_regex.findall(form_content)

                    for tag in input_tags:
                        parameter_name = tag[0]
                        original_value = tag[1] if len(tag) > 1 and tag[1] else "1"
                        form_parameters[parameter_name] = original_value

                    for parameter_name, original_value in form_parameters.items():
                        yield "GETPARAM", parameter_name, original_value, form_action, _exclude_key(
                            form_parameters, parameter_name
                        )

        def __init__(self, excavate):
            super().__init__(excavate)
            self.parameterExtractorCallbackDict = {}
            regexes_component_list = []
            parameterExtractorRules = find_subclasses(self, self.ParameterExtractorRule)
            for r in parameterExtractorRules:
                self.parameterExtractorCallbackDict[r.__name__] = r
                regexes_component_list.append(f"${r.__name__} = {r.extraction_regex}")
            regexes_component = " ".join(regexes_component_list)
            self.yaraRules[f"parameter_extraction"] = (
                rf'rule parameter_extraction {{meta: description = "Extract Parameters from Web Content" strings: {regexes_component} condition: any of them}}'
            )

        def in_bl(self, value):
            in_bl = False
            for bl_param in self.parameter_blacklist:
                if bl_param.lower() == value.lower():
                    in_bl = True
            return in_bl

        def url_unparse(self, param_type, parsed_url):
            if param_type == "GETPARAM":
                querystring = ""
            else:
                querystring = parsed_url.query
            return urlunparse(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    "",
                    querystring if self.excavate.retain_querystring else "",
                    "",
                )
            )

        async def process(self, r):
            for h in r.strings:
                results = set(h.instances)
                for result in results:
                    ParameterExtractorSubmoduleName = h.identifier.lstrip("$")
                    if ParameterExtractorSubmoduleName not in self.parameterExtractorCallbackDict.keys():
                        raise excavateError("ParameterExtractor YaraRule identified reference non-existent submodule")
                    parameterExtractorSubModule = self.parameterExtractorCallbackDict[ParameterExtractorSubmoduleName](
                        self.excavate, result
                    )
                    for (
                        parameter_type,
                        parameter_name,
                        original_value,
                        endpoint,
                        additional_params,
                    ) in parameterExtractorSubModule.extract():

                        self.excavate.debug(
                            f"Found Parameter [{parameter_name}] in [{parameterExtractorSubModule.name}] ParameterExtractor Submodule"
                        )

                        in_bl = False
                        endpoint = self.event.data["url"] if not endpoint else endpoint
                        url = (
                            endpoint
                            if endpoint.startswith(("http://", "https://"))
                            else f"{self.event.parsed_url.scheme}://{self.event.parsed_url.netloc}{endpoint}"
                        )

                        if self.in_bl(parameter_name) == False:
                            parsed_url = urlparse(url)
                            description = f"HTTP Extracted Parameter [{parameter_name}]"
                            data = {
                                "host": parsed_url.hostname,
                                "type": parameter_type,
                                "name": parameter_name,
                                "original_value": original_value,
                                "url": self.url_unparse(parameter_type, parsed_url),
                                "additional_params": additional_params,
                                "assigned_cookies": self.assigned_cookies,
                                "regex_name": parameterExtractorSubModule.name,
                            }
                            context = f"excavate's Parameter extractor found WEB_PARAMETER: {parameter_name} using technique [{parameterExtractorSubModule.name}]"
                            await self.report(data, context, event_type="WEB_PARAMETER")
                        else:
                            self.debug(f"blocked parameter [{parameter_name}] due to BL match")

    class URLExtractor(ExcavateRule):
        yaraRules = {
            "urlfull": r'rule urlfull { meta: description = "Contains full URL" strings: $url_full = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ condition: $url_full }',
            "urltag": r'rule urltag { meta: description = "Contains tag with src or href attribute" strings: $url_attr = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ condition: $url_attr }',
        }

        async def process(self, r):
            for h in r.strings:
                results = set(h.instances)
                for result in results:
                    context = f"excavate's URL extractor found URL_UNVERIFIED: {result} using regex search"
                    await self.report(result, context, event_type="URL_UNVERIFIED")

    class HostnameExtractor(ExcavateRule):
        yaraRules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            regexes_component_list = []
            if excavate.scan.dns_regexes:
                for i, r in enumerate(excavate.scan.dns_regexes):
                    regexes_component_list.append(rf"$dns_name_{i} = /\b{r.pattern}/ nocase")
                regexes_component = " ".join(regexes_component_list)
                self.yaraRules[f"hostname_extraction"] = (
                    rf'rule hostname_extraction {{meta: description = "Matches DNS hostname pattern" strings: {regexes_component} condition: any of them}}'
                )

        async def process(self, r):
            for h in r.strings:
                hostname_regex = re.compile(self.excavate.scan.dns_regexes[int(h.identifier.split("_")[-1])].pattern)
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

        modules_WEB_PARAMETER = [
            module_name
            for module_name, module in self.scan.modules.items()
            if "WEB_PARAMETER" in module.watched_events
        ]

        self.parameter_parsing = bool(modules_WEB_PARAMETER)

        self.retain_querystring = False
        if self.config.get("retain_querystring", False) == True:
            self.retain_querystring = True

        for module in self.scan.modules.values():
            if not str(module).startswith("_"):
                ExcavateRules = find_subclasses(module, ExcavateRule)
                for e in ExcavateRules:
                    if e.__name__ == "ParameterExtractor":
                        message = (
                            "Parameter Extraction disabled because no modules consume WEB_PARAMETER events"
                            if not self.parameter_parsing
                            else f"Parameter Extraction enabled because the following modules consume WEB_PARAMETER events: [{', '.join(modules_WEB_PARAMETER)}]"
                        )
                        self.debug(message) if not self.parameter_parsing else self.hugeinfo(message)
                    excavateRule = e(self)
                    for ruleName, ruleContent in excavateRule.yaraRules.items():
                        self.yaraRulesDict[ruleName] = ruleContent
                        self.yaraCallbackDict[ruleName] = excavateRule._callback
        # self.hugewarning(self.yaraRulesDict)
        self.yaraRules = yara.compile(source="\n".join(self.yaraRulesDict.values()))
        return True

    async def search(self, data, event, assigned_cookies, discovery_context="HTTP response"):
        for result in self.yaraRules.match(data=data):
            rule_name = result.rule
            if rule_name in self.yaraCallbackDict.keys():
                await self.yaraCallbackDict[rule_name](result, data, event, assigned_cookies, discovery_context)
            else:
                self.hugewarning(f"YARA Rule {rule_name} not found in pre-compiled rules")

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

        # process response data
        body = event.data.get("body", "")
        headers = event.data.get("raw_header", "")
        if body == "" and headers == "":
            return
        if self.recursive_decode:
            body = await self.helpers.re.recursive_decode(body)
            headers = await self.helpers.re.recursive_decode(headers)

        headers_dict = self.helpers.headers_string2dict(headers)
        assigned_cookies = {}
        for k, v in headers_dict.items():
            if k.lower() == "set_cookie":
                if "=" not in v:
                    self.debug(f"Cookie found without '=': {v}")
                    continue
                else:
                    cookie_name = v.split("=")[0]
                    cookie_value = v.split("=")[1].split(";")[0]

                    if self.in_bl(cookie_value) == False:
                        assigned_cookies[cookie_name] = cookie_value
                        description = f"Set-Cookie Assigned Cookie [{cookie_name}]"
                        data = {
                            "host": str(event.host),
                            "type": "COOKIE",
                            "name": cookie_name,
                            "original_value": cookie_value,
                            "url": self.url_unparse("COOKIE", event.parsed_url),
                            "description": description,
                        }
                        await self.emit_event(data, "WEB_PARAMETER", event)
                    else:
                        self.debug(f"blocked cookie parameter [{cookie_name}] due to BL match")
            if k.lower() == "location":
                for (
                    method,
                    parsed_url,
                    parameter_name,
                    original_value,
                    regex_name,
                    additional_params,
                ) in extract_params_location(v, event.parsed_url):
                    if self.in_bl(parameter_name) == False:
                        description = f"HTTP Extracted Parameter [{parameter_name}]"
                        data = {
                            "host": parsed_url.hostname,
                            "type": "GETPARAM",
                            "name": parameter_name,
                            "original_value": original_value,
                            "url": self.url_unparse("GETPARAM", parsed_url),
                            "description": description,
                            "additional_params": additional_params,
                        }
                        await self.emit_event(data, "WEB_PARAMETER", event)

        await self.search(
            body,
            event,
            assigned_cookies,
            #  consider_spider_danger=True,
            discovery_context="HTTP response (body)",
        )

        await self.search(
            headers,
            event,
            assigned_cookies,
            #  consider_spider_danger=True,
            discovery_context="HTTP response (headers)",
        )
