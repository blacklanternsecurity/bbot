import yara
import json
import html
import inspect
import regex as re
from pathlib import Path
from bbot.errors import ExcavateError
import bbot.core.helpers.regexes as bbot_regexes
from bbot.modules.internal.base import BaseInternalModule
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bbot.core.helpers.misc import parse_list_string


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
        yield "GET", parsed_url, p, p_value, "location_header", _exclude_key(flat_params, p)


class YaraRuleSettings:

    def __init__(self, description, tags, emit_match):
        self.description = description
        self.tags = tags
        self.emit_match = emit_match


class ExcavateRule:
    """
    The BBOT Regex Commandments:

    1) Thou shalt employ YARA regexes in place of Python regexes, save when necessity doth compel otherwise.
    2) Thou shalt ne'er wield a Python regex against a vast expanse of text.
    3) Whensoever it be possible, thou shalt favor string matching o'er regexes.

    Amen.
    """

    yara_rules = {}

    def __init__(self, excavate):
        self.excavate = excavate
        self.helpers = excavate.helpers
        self.name = ""

    async def preprocess(self, r, event, discovery_context):
        self.discovery_context = discovery_context

        description = ""
        tags = []
        emit_match = False

        if "description" in r.meta.keys():
            description = r.meta["description"]
        if "tags" in r.meta.keys():
            tags = parse_list_string(r.meta["tags"])
        if "emit_match" in r.meta.keys():
            emit_match = True

        yara_rule_settings = YaraRuleSettings(description, tags, emit_match)
        yara_results = {}
        for h in r.strings:
            yara_results[h.identifier.lstrip("$")] = sorted(set([i.matched_data.decode("utf-8") for i in h.instances]))
        await self.process(yara_results, event, yara_rule_settings)

    async def process(self, yara_results, event, yara_rule_settings):

        for identifier, results in yara_results.items():
            for result in results:
                event_data = {"host": str(event.host), "url": event.data.get("url", "")}
                event_data["description"] = f"{self.discovery_context} {yara_rule_settings.description}"
                if yara_rule_settings.emit_match:
                    event_data["description"] += f" [{result}]"
                await self.report(event_data, event, yara_rule_settings)

    async def report_prep(self, event_data, event_type, event, tags):
        event_draft = self.excavate.make_event(event_data, event_type, parent=event)
        if not event_draft:
            return None
        event_draft.tags = tags
        return event_draft

    async def report(self, event_data, event, yara_rule_settings, event_type="FINDING", abort_if=None, **kwargs):

        # If a description is not set and is needed, provide a basic one
        if event_type == "FINDING" and "description" not in event_data.keys():
            event_data["description"] = f"{self.discovery_context} {yara_rule_settings['self.description']}"
        subject = ""
        if isinstance(event_data, str):
            subject = f" event_data"
        context = f"Excavate's [{self.__class__.__name__}] submodule emitted [{event_type}]{subject}, because {self.discovery_context} {yara_rule_settings.description}"
        tags = yara_rule_settings.tags
        event_draft = await self.report_prep(event_data, event_type, event, tags, **kwargs)
        if event_draft:
            await self.excavate.emit_event(event_draft, context=context, abort_if=abort_if)


class CustomExtractor(ExcavateRule):

    def __init__(self, excavate):
        super().__init__(excavate)

    async def process(self, yara_results, event, yara_rule_settings):

        for identifier, results in yara_results.items():
            for result in results:
                event_data = {"host": str(event.host), "url": event.data.get("url", "")}
                description_string = (
                    f" with description: [{yara_rule_settings.description}]" if yara_rule_settings.description else ""
                )
                event_data["description"] = (
                    f"Custom Yara Rule [{self.name}]{description_string} Matched via identifier [{identifier}]"
                )
                if yara_rule_settings.emit_match:
                    event_data["description"] += f" and extracted [{result}]"
                await self.report(event_data, event, yara_rule_settings)


class excavate(BaseInternalModule):
    """
    Example (simple) Excavate Rules:

    class excavateTestRule(ExcavateRule):
        yara_rules = {
            "SearchForText": 'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
            "SearchForText2": 'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
        }
    """

    watched_events = ["HTTP_RESPONSE", "RAW_TEXT"]
    produced_events = ["URL_UNVERIFIED", "WEB_PARAMETER"]
    flags = ["passive"]
    meta = {
        "description": "Passively extract juicy tidbits from scan data",
        "created_date": "2022-06-27",
        "author": "@liquidsec",
    }

    options = {
        "retain_querystring": False,
        "yara_max_match_data": 2000,
        "custom_yara_rules": "",
    }
    options_desc = {
        "retain_querystring": "Keep the querystring intact on emitted WEB_PARAMETERS",
        "yara_max_match_data": "Sets the maximum amount of text that can extracted from a YARA regex",
        "custom_yara_rules": "Include custom Yara rules",
    }
    scope_distance_modifier = None

    _max_event_handlers = 8

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

    yara_rule_name_regex = re.compile(r"rule\s(\w+)\s{")
    yara_rule_regex = re.compile(r"(?s)((?:rule\s+\w+\s*{[^{}]*(?:{[^{}]*}[^{}]*)*[^{}]*(?:/\S*?}[^/]*?/)*)*})")

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
                querystring if self.retain_querystring else "",
                "",
            )
        )

    class ParameterExtractor(ExcavateRule):

        yara_rules = {}

        class ParameterExtractorRule:
            name = ""

            def extract(self):
                pass

            def __init__(self, excavate, result):
                self.excavate = excavate
                self.result = result

        class GetJquery(ParameterExtractorRule):

            name = "GET jquery"
            discovery_regex = r"/\$.get\([^\)].+\)/ nocase"
            extraction_regex = re.compile(r"\$.get\([\'\"](.+)[\'\"].+(\{.+\})\)")
            output_type = "GETPARAM"

            def convert_to_dict(self, extracted_str):
                extracted_str = extracted_str.replace("'", '"')
                extracted_str = re.sub(r"(\w+):", r'"\1":', extracted_str)
                try:
                    return json.loads(extracted_str)
                except json.JSONDecodeError as e:
                    self.excavate.debug(f"Failed to decode JSON: {e}")
                    return None

            def extract(self):
                extracted_results = self.extraction_regex.findall(str(self.result))
                if extracted_results:
                    for action, extracted_parameters in extracted_results:
                        extracted_parameters_dict = self.convert_to_dict(extracted_parameters)
                        for parameter_name, original_value in extracted_parameters_dict.items():
                            yield self.output_type, parameter_name, original_value, action, _exclude_key(
                                extracted_parameters_dict, parameter_name
                            )

        class PostJquery(GetJquery):
            name = "POST jquery"
            discovery_regex = r"/\$.post\([^\)].+\)/ nocase"
            extraction_regex = re.compile(r"\$.post\([\'\"](.+)[\'\"].+(\{.+\})\)")
            output_type = "POSTPARAM"

        class HtmlTags(ParameterExtractorRule):
            name = "HTML Tags"
            discovery_regex = r'/<[^>]+(href|src)=["\'][^"\']*["\'][^>]*>/ nocase'
            extraction_regex = bbot_regexes.tag_attribute_regex
            output_type = "GETPARAM"

            def extract(self):
                urls = self.extraction_regex.findall(str(self.result))
                for url in urls:
                    parsed_url = urlparse(url)
                    query_strings = parse_qs(parsed_url.query)
                    query_strings_dict = {
                        k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in query_strings.items()
                    }
                    for parameter_name, original_value in query_strings_dict.items():
                        if original_value == None or original_value == "":
                            original_value = 1
                        yield self.output_type, parameter_name, original_value, parsed_url.path, _exclude_key(
                            query_strings_dict, parameter_name
                        )

        class GetForm(ParameterExtractorRule):
            name = "GET Form"
            discovery_regex = r'/<form[^>]*\bmethod=["\']?get["\']?[^>]*>.*<\/form>/s nocase'
            form_content_regexes = [
                bbot_regexes.input_tag_regex,
                bbot_regexes.select_tag_regex,
                bbot_regexes.textarea_tag_regex,
            ]
            extraction_regex = bbot_regexes.get_form_regex
            output_type = "GETPARAM"

            def extract(self):
                forms = self.extraction_regex.findall(str(self.result))
                for form_action, form_content in forms:
                    form_parameters = {}
                    for form_content_regex in self.form_content_regexes:
                        input_tags = form_content_regex.findall(form_content)

                        for parameter_name, original_value in input_tags:
                            original_value
                            form_parameters[parameter_name] = original_value

                        for parameter_name, original_value in form_parameters.items():
                            yield self.output_type, parameter_name, original_value, form_action, _exclude_key(
                                form_parameters, parameter_name
                            )

        class PostForm(GetForm):
            name = "POST Form"
            discovery_regex = r'/<form[^>]*\bmethod=["\']?post["\']?[^>]*>.*<\/form>/s nocase'
            extraction_regex = bbot_regexes.post_form_regex
            output_type = "POSTPARAM"

        def __init__(self, excavate):
            super().__init__(excavate)
            self.parameterExtractorCallbackDict = {}
            regexes_component_list = []
            parameterExtractorRules = find_subclasses(self, self.ParameterExtractorRule)
            for r in parameterExtractorRules:
                self.excavate.verbose(f"Including ParameterExtractor Submodule: {r.__name__}")
                self.parameterExtractorCallbackDict[r.__name__] = r
                regexes_component_list.append(f"${r.__name__} = {r.discovery_regex}")
            regexes_component = " ".join(regexes_component_list)
            self.yara_rules[f"parameter_extraction"] = (
                rf'rule parameter_extraction {{meta: description = "contains POST form" strings: {regexes_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier, results in yara_results.items():
                for result in results:
                    if identifier not in self.parameterExtractorCallbackDict.keys():
                        raise ExcavateError("ParameterExtractor YaraRule identified reference non-existent submodule")
                    parameterExtractorSubModule = self.parameterExtractorCallbackDict[identifier](
                        self.excavate, result
                    )
                    extracted_params = parameterExtractorSubModule.extract()
                    if extracted_params:
                        for (
                            parameter_type,
                            parameter_name,
                            original_value,
                            endpoint,
                            additional_params,
                        ) in extracted_params:

                            self.excavate.debug(
                                f"Found Parameter [{parameter_name}] in [{parameterExtractorSubModule.name}] ParameterExtractor Submodule"
                            )
                            endpoint = event.data["url"] if not endpoint else endpoint
                            url = (
                                endpoint
                                if endpoint.startswith(("http://", "https://"))
                                else f"{event.parsed_url.scheme}://{event.parsed_url.netloc}{endpoint}"
                            )

                            if self.excavate.helpers.validate_parameter(parameter_name, parameter_type):

                                if self.excavate.in_bl(parameter_name) == False:
                                    parsed_url = urlparse(url)
                                    description = f"HTTP Extracted Parameter [{parameter_name}] ({parameterExtractorSubModule.name} Submodule)"
                                    data = {
                                        "host": parsed_url.hostname,
                                        "type": parameter_type,
                                        "name": parameter_name,
                                        "original_value": original_value,
                                        "url": self.excavate.url_unparse(parameter_type, parsed_url),
                                        "additional_params": additional_params,
                                        "assigned_cookies": self.excavate.assigned_cookies,
                                        "description": description,
                                    }
                                    await self.report(data, event, yara_rule_settings, event_type="WEB_PARAMETER")
                                else:
                                    self.excavate.debug(f"blocked parameter [{parameter_name}] due to BL match")
                            else:
                                self.excavate.debug(f"blocked parameter [{parameter_name}] due to validation failure")

    class CSPExtractor(ExcavateRule):
        yara_rules = {
            "csp": r'rule csp { meta: tags = "affiliate" description = "contains CSP Header" strings: $csp = /Content-Security-Policy:[^\r\n]+/ nocase condition: $csp }',
        }

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier in yara_results.keys():
                for csp_str in yara_results[identifier]:
                    domains = await self.helpers.re.findall(bbot_regexes.dns_name_regex, csp_str)
                    unique_domains = set(domains)
                    for domain in unique_domains:
                        await self.report(domain, event, yara_rule_settings, event_type="DNS_NAME")

    class EmailExtractor(ExcavateRule):

        yara_rules = {
            "email": 'rule email { meta: description = "contains email address" strings: $email = /[^\\W_][\\w\\-\\.\\+\']{0,100}@[a-zA-Z0-9\\-]{1,100}(\\.[a-zA-Z0-9\\-]{1,100})*\\.[a-zA-Z]{2,63}/ nocase fullword condition: $email }',
        }

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier in yara_results.keys():
                for email_str in yara_results[identifier]:
                    await self.report(email_str, event, yara_rule_settings, event_type="EMAIL_ADDRESS")

    # Future Work: Emit a JWT Object, and make a new Module to ingest it.
    class JWTExtractor(ExcavateRule):
        yara_rules = {
            "jwt": r'rule jwt { meta: emit_match = "True" description = "contains JSON Web Token (JWT)" strings: $jwt = /\beyJ[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*/ nocase condition: $jwt }',
        }

    class ErrorExtractor(ExcavateRule):

        signatures = {
            "PHP_1": r"/\.php on line [0-9]+/",
            "PHP_2": r"/\.php<\/b> on line <b>[0-9]+/",
            "PHP_3": '"Fatal error:"',
            "Microsoft_SQL_Server_1": r"/\[(ODBC SQL Server Driver|SQL Server|ODBC Driver Manager)\]/",
            "Microsoft_SQL_Server_2": '"You have an error in your SQL syntax; check the manual"',
            "Java_1": r"/\.java:[0-9]+/",
            "Java_2": r"/\.java\((Inlined )?Compiled Code\)/",
            "Perl": r"/at (\/[A-Za-z0-9\._]+)*\.pm line [0-9]+/",
            "Python": r"/File \"[A-Za-z0-9\-_\.\/]*\", line [0-9]+, in/",
            "Ruby": r"/\.rb:[0-9]+:in/",
            "ASPNET_1": '"Exception of type"',
            "ASPNET_2": '"--- End of inner exception stack trace ---"',
            "ASPNET_3": '"Microsoft OLE DB Provider"',
            "ASPNET_4": r"/Error ([\d-]+) \([\dA-F]+\)/",
        }
        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            signature_component_list = []
            for signature_name, signature in self.signatures.items():
                signature_component_list.append(rf"${signature_name} = {signature}")
            signature_component = " ".join(signature_component_list)
            self.yara_rules[f"error_detection"] = (
                f'rule error_detection {{meta: description = "contains a verbose error message" strings: {signature_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "host": str(event.host),
                        "url": event.data.get("url", ""),
                        "description": f"{self.discovery_context} {yara_rule_settings.description} ({identifier})",
                    }
                    await self.report(event_data, event, yara_rule_settings, event_type="FINDING")

    class SerializationExtractor(ExcavateRule):

        regexes = {
            "Java": re.compile(r"[^a-zA-Z0-9\/+]rO0[a-zA-Z0-9+\/]+={0,2}"),
            "DOTNET": re.compile(r"[^a-zA-Z0-9\/+]AAEAAAD\/\/[a-zA-Z0-9\/+]+={0,2}"),
            "PHP_Array": re.compile(r"[^a-zA-Z0-9\/+]YTo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "PHP_String": re.compile(r"[^a-zA-Z0-9\/+]czo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "PHP_Object": re.compile(r"[^a-zA-Z0-9\/+]Tzo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "Possible_Compressed": re.compile(r"[^a-zA-Z0-9\/+]H4sIAAAAAAAA[a-zA-Z0-9+\/]+={0,2}"),
        }
        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            regexes_component_list = []
            for regex_name, regex in self.regexes.items():
                regexes_component_list.append(rf"${regex_name} = /\b{regex.pattern}/ nocase")
            regexes_component = " ".join(regexes_component_list)
            self.yara_rules[f"serialization_detection"] = (
                f'rule serialization_detection {{meta: description = "contains a possible serialized object" strings: {regexes_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "host": str(event.host),
                        "url": event.data.get("url", ""),
                        "description": f"{self.discovery_context} {yara_rule_settings.description} ({identifier})",
                    }
                    await self.report(event_data, event, yara_rule_settings, event_type="FINDING")

    class FunctionalityExtractor(ExcavateRule):

        yara_rules = {
            "File_Upload_Functionality": r'rule File_Upload_Functionality { meta: description = "contains file upload functionality" strings: $fileuploadfunc = /<input[^>]+type=["\']?file["\']?[^>]+>/ nocase condition: $fileuploadfunc }',
            "Web_Service_WSDL": r'rule Web_Service_WSDL { meta: emit_match = "True" description = "contains a web service WSDL URL" strings: $wsdl = /https?:\/\/[^\s]*\.(wsdl)/ nocase condition: $wsdl }',
        }

    class NonHttpSchemeExtractor(ExcavateRule):
        yara_rules = {
            "Non_HTTP_Scheme": r'rule Non_HTTP_Scheme { meta: description = "contains non-http scheme URL" strings: $nonhttpscheme = /\b\w{2,35}:\/\/[\w.-]+(:\d+)?\b/ nocase fullword condition: $nonhttpscheme }'
        }

        scheme_blacklist = ["javascript", "mailto", "tel", "data", "vbscript", "about", "file"]

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier, results in yara_results.items():
                for url_str in results:
                    scheme = url_str.split("://")[0]
                    if scheme in self.scheme_blacklist:
                        continue
                    if scheme not in self.excavate.valid_schemes:
                        continue
                    try:
                        parsed_url = urlparse(url_str)
                    except Exception as e:
                        self.excavate.debug(f"Error parsing URI {url_str}: {e}")
                        continue
                    netloc = getattr(parsed_url, "netloc", None)
                    if netloc is None:
                        continue
                    try:
                        host, port = self.excavate.helpers.split_host_port(parsed_url.netloc)
                    except ValueError as e:
                        self.excavate.debug(f"Failed to parse netloc: {e}")
                        continue
                    if parsed_url.scheme in ["http", "https"]:
                        continue
                    abort_if = lambda e: e.scope_distance > 0
                    finding_data = {"host": str(host), "description": f"Non-HTTP URI: {parsed_url.geturl()}"}
                    await self.report(finding_data, event, yara_rule_settings, abort_if=abort_if)
                    protocol_data = {"protocol": parsed_url.scheme, "host": str(host)}
                    if port:
                        protocol_data["port"] = port
                    await self.report(
                        protocol_data, event, yara_rule_settings, event_type="PROTOCOL", abort_if=abort_if
                    )

    class URLExtractor(ExcavateRule):
        yara_rules = {
            "url_full": r'rule url_full { meta: tags = "spider-danger" description = "contains full URL" strings: $url_full = /https?:\/\/([\w\.-]+)([:\/\w\.-]*)/ condition: $url_full }',
            "url_attr": r'rule url_attr { meta: tags = "spider-danger" description = "contains tag with src or href attribute" strings: $url_attr = /<[^>]+(href|src)=["\'][^"\']*["\'][^>]*>/ condition: $url_attr }',
        }
        full_url_regex = re.compile(r"(https?)://((?:\w|\d)(?:[\d\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]*[-\w\.]+)*/?)")
        full_url_regex_strict = re.compile(r"^(https?):\/\/([\w.-]+)(?::\d{1,5})?(\/[\w\/\.-]*)?(\?[^\s]+)?$")
        tag_attribute_regex = bbot_regexes.tag_attribute_regex

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.web_spider_links_per_page = self.excavate.scan.config.get("web_spider_links_per_page", 20)

        async def process(self, yara_results, event, yara_rule_settings):

            for identifier, results in yara_results.items():
                urls_found = 0
                for url_str in results:
                    if identifier == "url_full":
                        if not await self.helpers.re.search(self.full_url_regex, url_str):
                            self.excavate.debug(
                                f"Rejecting potential full URL [{url_str}] as did not match full_url_regex"
                            )
                            continue
                        final_url = url_str

                        self.excavate.debug(f"Discovered Full URL [{final_url}]")
                    elif identifier == "url_attr":
                        m = await self.helpers.re.search(self.tag_attribute_regex, url_str)
                        if not m:
                            self.excavate.debug(
                                f"Rejecting potential attribute URL [{url_str}] as did not match tag_attribute_regex"
                            )
                            continue
                        unescaped_url = html.unescape(m.group(1))
                        source_url = event.parsed_url.geturl()
                        final_url = urljoin(source_url, unescaped_url)
                        if not await self.helpers.re.search(self.full_url_regex_strict, final_url):
                            self.excavate.debug(
                                f"Rejecting reconstructed URL [{final_url}] as did not match full_url_regex_strict"
                            )
                            continue
                        self.excavate.debug(
                            f"Reconstructed Full URL [{final_url}] from extracted relative URL [{unescaped_url}] "
                        )

                    if self.excavate.scan.in_scope(final_url):
                        urls_found += 1

                    await self.report(
                        final_url, event, yara_rule_settings, event_type="URL_UNVERIFIED", urls_found=urls_found
                    )

        async def report_prep(self, event_data, event_type, event, tags, **kwargs):
            event_draft = self.excavate.make_event(event_data, event_type, parent=event)
            if not event_draft:
                return None
            url_in_scope = self.excavate.scan.in_scope(event_draft)
            urls_found = kwargs.get("urls_found", None)
            if urls_found:
                exceeds_max_links = urls_found > self.web_spider_links_per_page and url_in_scope
                if exceeds_max_links:
                    tags.append("spider-max")
            event_draft.tags = tags
            return event_draft

    class HostnameExtractor(ExcavateRule):
        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            regexes_component_list = []
            if excavate.scan.dns_regexes_yara:
                for i, r in enumerate(excavate.scan.dns_regexes_yara):
                    regexes_component_list.append(rf"$dns_name_{i} = /\b{r.pattern}/ nocase")
                regexes_component = " ".join(regexes_component_list)
                self.yara_rules[f"hostname_extraction"] = (
                    f'rule hostname_extraction {{meta: description = "matches DNS hostname pattern derived from target(s)" strings: {regexes_component} condition: any of them}}'
                )

        async def process(self, yara_results, event, yara_rule_settings):
            for identifier in yara_results.keys():
                for domain_str in yara_results[identifier]:
                    await self.report(domain_str, event, yara_rule_settings, event_type="DNS_NAME")

    def add_yara_rule(self, rule_name, rule_content, rule_instance):
        rule_instance.name = rule_name
        self.yara_rules_dict[rule_name] = rule_content
        self.yara_preprocess_dict[rule_name] = rule_instance.preprocess

    async def extract_yara_rules(self, rules_content):
        for r in await self.helpers.re.findall(self.yara_rule_regex, rules_content):
            yield r

    async def setup(self):

        max_redirects = self.scan.config.get("http_max_redirects", 5)
        self.web_spider_distance = self.scan.config.get("web_spider_distance", 0)
        self.max_redirects = max(max_redirects, self.web_spider_distance)
        self.yara_rules_dict = {}
        self.yara_preprocess_dict = {}

        modules_WEB_PARAMETER = [
            module_name
            for module_name, module in self.scan.modules.items()
            if "WEB_PARAMETER" in module.watched_events
        ]

        self.parameter_extraction = bool(modules_WEB_PARAMETER)

        self.retain_querystring = False
        if self.config.get("retain_querystring", False) == True:
            self.retain_querystring = True

        for module in self.scan.modules.values():
            if not str(module).startswith("_"):
                ExcavateRules = find_subclasses(module, ExcavateRule)
                for e in ExcavateRules:
                    self.verbose(f"Including Submodule {e.__name__}")
                    if e.__name__ == "ParameterExtractor":
                        message = (
                            "Parameter Extraction disabled because no modules consume WEB_PARAMETER events"
                            if not self.parameter_extraction
                            else f"Parameter Extraction enabled because the following modules consume WEB_PARAMETER events: [{', '.join(modules_WEB_PARAMETER)}]"
                        )
                        self.debug(message) if not self.parameter_extraction else self.hugeinfo(message)
                        # do not add parameter extraction yara rules if it's disabled
                        if not self.parameter_extraction:
                            continue
                    excavateRule = e(self)
                    for rule_name, rule_content in excavateRule.yara_rules.items():
                        self.add_yara_rule(rule_name, rule_content, excavateRule)

        self.custom_yara_rules = str(self.config.get("custom_yara_rules", ""))
        if self.custom_yara_rules:
            custom_rules_count = 0
            if Path(self.custom_yara_rules).is_file():
                with open(self.custom_yara_rules) as f:
                    rules_content = f.read()
                self.debug(f"Successfully loaded secrets file [{self.custom_yara_rules}]")
            else:
                self.debug(f"Custom secrets is NOT a file. Will attempt to treat it as rule content")
                rules_content = self.custom_yara_rules

            self.debug(f"Final combined yara rule contents: {rules_content}")
            custom_yara_rule_processed = self.extract_yara_rules(rules_content)
            async for rule_content in custom_yara_rule_processed:
                try:
                    yara.compile(source=rule_content)
                except yara.SyntaxError as e:
                    self.hugewarning(f"Custom Yara rule failed to compile: {e}")
                    return False

                rule_match = await self.helpers.re.search(self.yara_rule_name_regex, rule_content)
                if not rule_match:
                    self.hugewarning(f"Custom Yara formatted incorrectly: could not find rule name")
                    return False

                rule_name = rule_match.groups(1)[0]
                c = CustomExtractor(self)
                self.add_yara_rule(rule_name, rule_content, c)
                custom_rules_count += 1
            if custom_rules_count > 0:
                self.hugeinfo(f"Successfully added {str(custom_rules_count)} custom Yara rule(s)")

        yara_max_match_data = self.config.get("yara_max_match_data", 2000)

        yara.set_config(max_match_data=yara_max_match_data)
        yara_rules_combined = "\n".join(self.yara_rules_dict.values())
        try:
            self.yara_rules = yara.compile(source=yara_rules_combined)
        except yara.SyntaxError as e:
            self.hugewarning(f"Yara Rules failed to compile with error: [{e}]")
            self.debug(yara_rules_combined)
            return False

        # pre-load valid URL schemes
        valid_schemes_filename = self.helpers.wordlist_dir / "valid_url_schemes.txt"
        self.valid_schemes = set(self.helpers.read_file(valid_schemes_filename))

        return True

    async def search(self, data, event, content_type, discovery_context="HTTP response"):
        if not data:
            return None

        decoded_data = await self.helpers.re.recursive_decode(data)

        content_type_lower = content_type.lower() if content_type else ""
        extraction_map = {
            "json": self.helpers.extract_params_json,
            "xml": self.helpers.extract_params_xml,
        }

        for source_type, extract_func in extraction_map.items():
            if source_type in content_type_lower:
                results = extract_func(data)
                if results:
                    for parameter_name, original_value in results:
                        description = (
                            f"HTTP Extracted Parameter (speculative from {source_type} content) [{parameter_name}]"
                        )
                        data = {
                            "host": str(event.host),
                            "type": "SPECULATIVE",
                            "name": parameter_name,
                            "original_value": original_value,
                            "url": str(event.data["url"]),
                            "additional_params": {},
                            "assigned_cookies": self.assigned_cookies,
                            "description": description,
                        }
                        context = f"excavate's Parameter extractor found a speculative WEB_PARAMETER: {parameter_name} by parsing {source_type} data from {str(event.host)}"
                        await self.emit_event(data, "WEB_PARAMETER", event, context=context)
                return

        for result in self.yara_rules.match(data=f"{data}\n{decoded_data}"):
            rule_name = result.rule
            if rule_name in self.yara_preprocess_dict:
                await self.yara_preprocess_dict[rule_name](result, event, discovery_context)
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
                            context=f'evcavate looked in "Location" header and found {url_event.type}: {url_event.data}',
                        )
                else:
                    self.verbose(f"Exceeded max HTTP redirects ({self.max_redirects}): {location}")

        # process response data
        body = event.data.get("body", "")
        headers = event.data.get("header-dict", "")
        headers_str = event.data.get("raw_header", "")
        if body == "" and headers == "":
            return

        self.assigned_cookies = {}
        content_type = None
        for k, v in headers.items():
            if k.lower() == "set_cookie":
                if "=" not in v:
                    self.debug(f"Cookie found without '=': {v}")
                    continue
                else:
                    cookie_name = v.split("=")[0]
                    cookie_value = v.split("=")[1].split(";")[0]

                    if self.in_bl(cookie_value) == False:
                        self.assigned_cookies[cookie_name] = cookie_value
                        description = f"Set-Cookie Assigned Cookie [{cookie_name}]"
                        data = {
                            "host": str(event.host),
                            "type": "COOKIE",
                            "name": cookie_name,
                            "original_value": cookie_value,
                            "url": self.url_unparse("COOKIE", event.parsed_url),
                            "description": description,
                        }
                        context = f"Excavate noticed a set-cookie header for cookie [{cookie_name}] and emitted a WEB_PARAMETER for it"
                        await self.emit_event(data, "WEB_PARAMETER", event, context=context)
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
                        description = f"HTTP Extracted Parameter [{parameter_name}] (Location Header)"
                        data = {
                            "host": parsed_url.hostname,
                            "type": "GETPARAM",
                            "name": parameter_name,
                            "original_value": original_value,
                            "url": self.url_unparse("GETPARAM", parsed_url),
                            "description": description,
                            "additional_params": additional_params,
                        }
                        context = f"Excavate parsed a location header for parameters and found [GETPARAM] Parameter Name: [{parameter_name}] and emitted a WEB_PARAMETER for it"
                        await self.emit_event(data, "WEB_PARAMETER", event, context=context)
            if k.lower() == "content-type":
                content_type = headers["content-type"]
        await self.search(
            body,
            event,
            content_type,
            discovery_context="HTTP response (body)",
        )
        await self.search(
            headers_str,
            event,
            content_type,
            discovery_context="HTTP response (headers)",
        )
