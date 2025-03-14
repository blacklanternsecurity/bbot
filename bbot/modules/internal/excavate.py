import yara
import json
import html
import time
import inspect
import regex as re
from pathlib import Path
from bbot.errors import ExcavateError
import bbot.core.helpers.regexes as bbot_regexes
from bbot.modules.base import BaseInterceptModule
from bbot.modules.internal.base import BaseInternalModule
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urldefrag


def find_subclasses(obj, base_class):
    """
    Finds and returns subclasses of a specified base class within an object.

    Parameters:
    obj : object
        The object to inspect for subclasses.
    base_class : type
        The base class to find subclasses of.

    Returns:
    list
        A list of subclasses found within the object.

    Example:
    >>> class A: pass
    >>> class B(A): pass
    >>> class C(A): pass
    >>> find_subclasses(locals(), A)
    [<class '__main__.B'>, <class '__main__.C'>]
    """
    subclasses = []
    for name, member in inspect.getmembers(obj):
        if inspect.isclass(member) and issubclass(member, base_class) and member is not base_class:
            subclasses.append(member)
    return subclasses


def _exclude_key(original_dict, key_to_exclude):
    """
    Returns a new dictionary excluding the specified key from the original dictionary.

    Parameters:
    original_dict : dict
        The dictionary to exclude the key from.
    key_to_exclude : hashable
        The key to exclude.

    Returns:
    dict
        A new dictionary without the specified key.

    Example:
    >>> original = {'a': 1, 'b': 2, 'c': 3}
    >>> _exclude_key(original, 'b')
    {'a': 1, 'c': 3}
    """
    return {key: value for key, value in original_dict.items() if key != key_to_exclude}


def extract_params_url(parsed_url):
    params = parse_qs(parsed_url.query)
    flat_params = {k: v[0] for k, v in params.items()}

    for p, p_value in flat_params.items():
        yield "GET", parsed_url, p, p_value, "direct_url", _exclude_key(flat_params, p)


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
        """
        Preprocesses YARA rule results, extracts meta tags, and configures a YaraRuleSettings object.

        This method retrieves optional meta tags from YARA rules and uses them to configure a YaraRuleSettings object.
        It formats the results from the YARA engine into a suitable format for the process() method and initiates
        a call to process(), passing on the pre-processed YARA results, event data, YARA rule settings, and discovery context.

        This should typically NOT be overridden.

        Parameters:
        r : YaraMatch
            The YARA match object containing the rule and meta information.
        event : Event
            The event data associated with the YARA match.
        discovery_context : DiscoveryContext
            The context in which the discovery is made.

        Returns:
        None
        """
        description = ""
        tags = []
        emit_match = False

        if "description" in r.meta.keys():
            description = r.meta["description"]
        if "tags" in r.meta.keys():
            tags = self.excavate.helpers.chain_lists(r.meta["tags"])
        if "emit_match" in r.meta.keys():
            emit_match = True

        yara_rule_settings = YaraRuleSettings(description, tags, emit_match)
        yara_results = {}
        for h in r.strings:
            yara_results[h.identifier.lstrip("$")] = sorted(
                {i.matched_data.decode("utf-8", errors="ignore") for i in h.instances}
            )
        await self.process(yara_results, event, yara_rule_settings, discovery_context)

    async def process(self, yara_results, event, yara_rule_settings, discovery_context):
        """
        Processes YARA rule results and reports events with enriched data.

        This method iterates over the provided YARA rule results and constructs event data for each match.
        It enriches the event data with host, URL, and description information, and conditionally includes
        matched data based on the YaraRuleSettings. Finally, it reports the constructed event data.

        Override when custom processing and/or validation is needed on data before reporting.

        Parameters:
        yara_results : dict
            A dictionary where keys are YARA rule identifiers and values are lists of matched data strings.
        event : Event
            The event data associated with the YARA match.
        yara_rule_settings : YaraRuleSettings
            The settings configured from YARA rule meta tags, including description, tags, and emit_match flag.
        discovery_context : DiscoveryContext
            The context in which the discovery is made.

        Returns:
        None
        """
        for results in yara_results.values():
            for result in results:
                event_data = {"description": f"{discovery_context} {yara_rule_settings.description}"}
                if yara_rule_settings.emit_match:
                    event_data["description"] += f" [{result}]"
                await self.report(event_data, event, yara_rule_settings, discovery_context)

    async def report_prep(self, event_data, event_type, event, tags):
        """
        Prepares an event draft for reporting by creating and tagging the event.

        This method creates an event draft using the provided event data and type, associating it with a parent event.
        It tags the event draft with the provided tags and returns the draft. If event creation fails, it returns None.

        Override when an event needs to be modified before it is emitted - for example, custom tags need to be conditionally added.

        Parameters:
        event_data : dict
            The data to be included in the event.
        event_type : str
            The type of the event being reported.
        event : Event
            The parent event to which this event draft is related.
        tags : list
            A list of tags to be associated with the event draft.

        Returns:
        EventDraft or None
        """
        event_draft = self.excavate.make_event(event_data, event_type, parent=event)
        if not event_draft:
            return None
        event_draft.add_tags(tags)
        return event_draft

    async def report(
        self, event_data, event, yara_rule_settings, discovery_context, event_type="FINDING", abort_if=None, **kwargs
    ):
        """
        Reports an event by preparing an event draft and emitting it.

        Processes the provided event data, sets a default description if needed, prepares the event draft, and emits it.
        It constructs a context string for the event and uses the report_prep method to create the event draft. If the draft is successfully
        created, it emits the event.

        Typically not overridden, but might need to be if custom logic is needed to build description/context, etc.

        Parameters:
        event_data : dict
            The data to be included in the event.
        event : Event
            The parent event to which this event is related.
        yara_rule_settings : YaraRuleSettings
            The settings configured from YARA rule meta tags, including description and tags.
        discovery_context : DiscoveryContext
            The context in which the discovery is made.
        event_type : str, optional
            The type of the event being reported, default is "FINDING".
        abort_if : callable, optional
            A callable that determines if the event emission should be aborted.
        **kwargs : dict
            Additional keyword arguments to pass to the report_prep method.

        Returns:
        None
        """

        # If a description is not set and is needed, provide a basic one
        if event_type == "FINDING" and "description" not in event_data.keys():
            event_data["description"] = f"{discovery_context} {yara_rule_settings['self.description']}"
        subject = ""
        if isinstance(event_data, str):
            subject = f" {event_data}"
        context = f"Excavate's {self.__class__.__name__} emitted {event_type}{subject}, because {discovery_context} {yara_rule_settings.description}"
        tags = yara_rule_settings.tags
        event_draft = await self.report_prep(event_data, event_type, event, tags, **kwargs)
        if event_draft:
            await self.excavate.emit_event(event_draft, context=context, abort_if=abort_if)


class CustomExtractor(ExcavateRule):
    description = "Enables custom, user-defined YARA rules."

    def __init__(self, excavate):
        super().__init__(excavate)

    async def process(self, yara_results, event, yara_rule_settings, discovery_context):
        for identifier, results in yara_results.items():
            for result in results:
                event_data = {}
                description_string = (
                    f" with description: [{yara_rule_settings.description}]" if yara_rule_settings.description else ""
                )
                event_data["description"] = (
                    f"Custom Yara Rule [{self.name}]{description_string} Matched via identifier [{identifier}]"
                )
                if yara_rule_settings.emit_match:
                    event_data["description"] += f" and extracted [{result}]"
                await self.report(event_data, event, yara_rule_settings, discovery_context)


class excavate(BaseInternalModule, BaseInterceptModule):
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
    accept_dupes = False

    _module_threads = 8

    parameter_blacklist = {
        p.lower()
        for p in [
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
    }

    yara_rule_name_regex = re.compile(r"rule\s(\w+)\s{")
    yara_rule_regex = re.compile(r"(?s)((?:rule\s+\w+\s*{[^{}]*(?:{[^{}]*}[^{}]*)*[^{}]*(?:/\S*?}[^/]*?/)*)*})")

    def in_bl(self, value):
        return value.lower() in self.parameter_blacklist

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
        description = "Extracts web parameters. Enabled if any modules are enabled that emit WEB_PARAMETER events."
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
                            yield (
                                self.output_type,
                                parameter_name,
                                original_value,
                                action,
                                _exclude_key(extracted_parameters_dict, parameter_name),
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
                        yield (
                            self.output_type,
                            parameter_name,
                            original_value,
                            url,
                            _exclude_key(query_strings_dict, parameter_name),
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
                            form_parameters[parameter_name] = original_value

                        for parameter_name, original_value in form_parameters.items():
                            yield (
                                self.output_type,
                                parameter_name,
                                original_value,
                                form_action,
                                _exclude_key(form_parameters, parameter_name),
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
            self.yara_rules["parameter_extraction"] = (
                rf'rule parameter_extraction {{meta: description = "contains POST form" strings: {regexes_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
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
                                if self.excavate.in_bl(parameter_name) is False:
                                    parsed_url = urlparse(url)
                                    if not parsed_url.hostname:
                                        self.excavate.warning(
                                            f"Error Parsing reconstructed URL [{url}] during parameter extraction, missing hostname"
                                        )
                                        continue
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
                                    await self.report(
                                        data, event, yara_rule_settings, discovery_context, event_type="WEB_PARAMETER"
                                    )
                                else:
                                    self.excavate.debug(f"blocked parameter [{parameter_name}] due to BL match")
                            else:
                                self.excavate.debug(f"blocked parameter [{parameter_name}] due to validation failure")

    class CSPExtractor(ExcavateRule):
        description = "Extracts domains from CSP headers."

        yara_rules = {
            "csp": r'rule csp { meta: tags = "affiliate" description = "contains CSP Header" strings: $csp = /Content-Security-Policy:[^\r\n]+/ nocase condition: $csp }',
        }

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for csp_str in yara_results[identifier]:
                    domains = await self.excavate.scan.extract_in_scope_hostnames(csp_str)
                    for domain in domains:
                        await self.report(domain, event, yara_rule_settings, discovery_context, event_type="DNS_NAME")

    class EmailExtractor(ExcavateRule):
        description = "Extract email addresses."

        yara_rules = {
            "email": 'rule email { meta: description = "contains email address" strings: $email = /[^\\W_][\\w\\-\\.\\+\']{0,100}@[a-zA-Z0-9\\-]{1,100}(\\.[a-zA-Z0-9\\-]{1,100})*\\.[a-zA-Z]{2,63}/ nocase fullword condition: $email }',
        }

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for email_str in yara_results[identifier]:
                    await self.report(
                        email_str, event, yara_rule_settings, discovery_context, event_type="EMAIL_ADDRESS"
                    )

    # Future Work: Emit a JWT Object, and make a new Module to ingest it.
    class JWTExtractor(ExcavateRule):
        description = "Extracts JSON Web Tokens."
        yara_rules = {
            "jwt": r'rule jwt { meta: emit_match = "True" description = "contains JSON Web Token (JWT)" strings: $jwt = /\beyJ[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*/ nocase condition: $jwt }',
        }

    class ErrorExtractor(ExcavateRule):
        description = "Identifies error messages from various platforms."
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
            self.yara_rules["error_detection"] = (
                f'rule error_detection {{meta: description = "contains a verbose error message" strings: {signature_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "description": f"{discovery_context} {yara_rule_settings.description} ({identifier})"
                    }
                    await self.report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING")

    class SerializationExtractor(ExcavateRule):
        description = "Identifies serialized objects from various platforms."
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
            self.yara_rules["serialization_detection"] = (
                f'rule serialization_detection {{meta: description = "contains a possible serialized object" strings: {regexes_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "description": f"{discovery_context} {yara_rule_settings.description} ({identifier})"
                    }
                    await self.report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING")

    class FunctionalityExtractor(ExcavateRule):
        description = "Detects potentially exploitable functionality and attack surface in web applications."
        yara_rules = {
            "File_Upload_Functionality": r'rule File_Upload_Functionality { meta: description = "contains file upload functionality" strings: $fileuploadfunc = /<input[^>]+type=["\']?file["\']?[^>]+>/ nocase condition: $fileuploadfunc }',
            "Web_Service_WSDL": r'rule Web_Service_WSDL { meta: emit_match = "True" description = "contains a web service WSDL URL" strings: $wsdl = /https?:\/\/[^\s]*\.(wsdl)/ nocase condition: $wsdl }',
        }

    class NonHttpSchemeExtractor(ExcavateRule):
        description = "Detects URIs with non-HTTP schemes."
        yara_rules = {
            "Non_HTTP_Scheme": r'rule Non_HTTP_Scheme { meta: description = "contains non-http scheme URL" strings: $nonhttpscheme = /\b\w{2,35}:\/\/[\w.-]+(:\d+)?\b/ nocase fullword condition: $nonhttpscheme }'
        }

        scheme_blacklist = ["javascript", "mailto", "tel", "data", "vbscript", "about", "file"]

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for results in yara_results.values():
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

                    def abort_if(e):
                        return e.scope_distance > 0

                    finding_data = {"host": str(host), "description": f"Non-HTTP URI: {parsed_url.geturl()}"}
                    await self.report(finding_data, event, yara_rule_settings, discovery_context, abort_if=abort_if)
                    protocol_data = {"protocol": parsed_url.scheme, "host": str(host)}
                    if port:
                        protocol_data["port"] = port
                    await self.report(
                        protocol_data,
                        event,
                        yara_rule_settings,
                        discovery_context,
                        event_type="PROTOCOL",
                        abort_if=abort_if,
                    )

    class URLExtractor(ExcavateRule):
        description = "Extracts URLs."
        yara_rules = {
            "url_full": (
                r"""
                rule url_full {
                    meta:
                        tags = "spider-danger"
                        description = "contains full URL"
                    strings:
                        $url_full = /https?:\/\/([\w\.-]+)(:\d{1,5})?([\/\w\.-]*)/
                    condition:
                        $url_full
                }
                """
            ),
            "url_attr": (
                r"""
                rule url_attr {
                    meta:
                        tags = "spider-danger"
                        description = "contains tag with src or href attribute"
                    strings:
                        $url_attr = /<[^>]+(href|src)=["\'][^"\']*["\'][^>]*>/
                    condition:
                        $url_attr
                }
                """
            ),
        }
        full_url_regex = re.compile(r"(https?)://(\w(?:[\w-]+\.?)+(?::\d{1,5})?(?:/[-\w\.\(\)]*[-\w\.]+)*/?)")
        full_url_regex_strict = re.compile(r"^(https?):\/\/([\w.-]+)(?::\d{1,5})?(\/[\w\/\.-]*)?(\?[^\s]+)?$")
        tag_attribute_regex = bbot_regexes.tag_attribute_regex

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier, results in yara_results.items():
                urls_found = 0
                final_url = ""
                for url_str in results:
                    if identifier == "url_full":
                        if not await self.helpers.re.search(self.full_url_regex, url_str):
                            self.excavate.debug(
                                f"Rejecting potential full URL [{url_str}] as did not match full_url_regex"
                            )
                            continue
                        final_url = url_str

                        self.excavate.debug(f"Discovered Full URL [{final_url}]")
                    elif identifier == "url_attr" and hasattr(event, "parsed_url"):
                        m = await self.helpers.re.search(self.tag_attribute_regex, url_str)
                        if not m:
                            self.excavate.debug(
                                f"Rejecting potential attribute URL [{url_str}] as did not match tag_attribute_regex"
                            )
                            continue
                        unescaped_url = html.unescape(m.group(1))
                        source_url = event.parsed_url.geturl()
                        final_url = urldefrag(urljoin(source_url, unescaped_url)).url
                        if not await self.helpers.re.search(self.full_url_regex_strict, final_url):
                            self.excavate.debug(
                                f"Rejecting reconstructed URL [{final_url}] as did not match full_url_regex_strict"
                            )
                            continue
                        self.excavate.debug(
                            f"Reconstructed Full URL [{final_url}] from extracted relative URL [{unescaped_url}] "
                        )

                    if final_url:
                        if self.excavate.scan.in_scope(final_url):
                            urls_found += 1

                        await self.report(
                            final_url,
                            event,
                            yara_rule_settings,
                            discovery_context,
                            event_type="URL_UNVERIFIED",
                            urls_found=urls_found,
                        )

        async def report_prep(self, event_data, event_type, event, tags, **kwargs):
            event_draft = self.excavate.make_event(event_data, event_type, parent=event)
            if not event_draft:
                return None
            url_in_scope = self.excavate.scan.in_scope(event_draft)
            urls_found = kwargs.get("urls_found", None)
            if urls_found:
                exceeds_max_links = urls_found > self.excavate.scan.web_spider_links_per_page and url_in_scope
                if exceeds_max_links:
                    tags.append("spider-max")
            event_draft.add_tags(tags)
            return event_draft

    class HostnameExtractor(ExcavateRule):
        description = "DNS name discovery, based on the scan target."

        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            self.yara_rules.update(excavate.scan.dns_yara_rules_uncompiled)

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for domain_str in yara_results[identifier]:
                    await self.report(domain_str, event, yara_rule_settings, discovery_context, event_type="DNS_NAME")

    class LoginPageExtractor(ExcavateRule):
        description = "Detects login pages with username and password fields."
        yara_rules = {
            "login_page": r"""
            rule login_page {
                meta:
                    description = "Detects login pages with username and password fields"
                strings:
                    $username_field = /<input[^>]+name=["']?(user|login|email)/ nocase
                    $password_field = /<input[^>]+name=["']?passw?/ nocase
                condition:
                    $username_field and $password_field
            }
            """
        }

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            if yara_results:
                event.add_tag("login-page")

    def add_yara_rule(self, rule_name, rule_content, rule_instance):
        rule_instance.name = rule_name
        self.yara_rules_dict[rule_name] = rule_content
        self.yara_preprocess_dict[rule_name] = rule_instance.preprocess

    async def extract_yara_rules(self, rules_content):
        for r in await self.helpers.re.findall(self.yara_rule_regex, rules_content):
            yield r

    async def setup(self):
        self.yara_rules_dict = {}
        self.yara_preprocess_dict = {}

        modules_WEB_PARAMETER = [
            module_name
            for module_name, module in self.scan.modules.items()
            if "WEB_PARAMETER" in module.watched_events
        ]

        self.parameter_extraction = bool(modules_WEB_PARAMETER)

        self.retain_querystring = False
        if self.config.get("retain_querystring", False) is True:
            self.retain_querystring = True

        for module in self.scan.modules.values():
            if not str(module).startswith("_"):
                ExcavateRules = find_subclasses(module, ExcavateRule)
                for e in ExcavateRules:
                    self.debug(f"Including Submodule {e.__name__}")
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
                self.debug(f"Successfully loaded custom yara rules file [{self.custom_yara_rules}]")
            else:
                self.debug("Custom yara rules file is NOT a file. Will attempt to treat it as rule content")
                rules_content = self.custom_yara_rules

            self.debug(f"Final combined yara rule contents: {rules_content}")
            custom_yara_rule_processed = self.extract_yara_rules(rules_content)
            async for rule_content in custom_yara_rule_processed:
                try:
                    yara.compile(source=rule_content)
                except yara.SyntaxError as e:
                    return False, f"Custom Yara rule failed to compile: {e}"

                rule_match = await self.helpers.re.search(self.yara_rule_name_regex, rule_content)
                if not rule_match:
                    return False, "Custom Yara formatted incorrectly: could not find rule name"

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
            start = time.time()
            self.verbose(f"Compiling {len(self.yara_rules_dict):,} YARA rules")
            for rule_name, rule_content in self.yara_rules_dict.items():
                self.debug(f"  - {rule_name}")
            self.yara_rules = yara.compile(source=yara_rules_combined)
            self.verbose(f"{len(self.yara_rules_dict):,} YARA rules compiled in {time.time() - start:.2f} seconds")
        except yara.SyntaxError as e:
            self.debug(yara_rules_combined)
            return False, f"Yara Rules failed to compile with error: [{e}]"

        # pre-load valid URL schemes
        valid_schemes_filename = self.helpers.wordlist_dir / "valid_url_schemes.txt"
        self.valid_schemes = set(self.helpers.read_file(valid_schemes_filename))

        self.url_querystring_remove = self.scan.config.get("url_querystring_remove", True)

        return True

    async def search(self, data, event, content_type, discovery_context="HTTP response"):
        if not data:
            return None

        decoded_data = await self.helpers.re.recursive_decode(data)

        if self.parameter_extraction:
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

    async def handle_event(self, event, **kwargs):
        if event.type == "HTTP_RESPONSE":
            # Harvest GET parameters from URL, if it came directly from the target, and parameter extraction is enabled
            if (
                self.parameter_extraction is True
                and self.url_querystring_remove is False
                and str(event.parent.parent.module) == "TARGET"
            ):
                self.debug(f"Processing target URL [{urlunparse(event.parsed_url)}] for GET parameters")
                for (
                    method,
                    parsed_url,
                    parameter_name,
                    original_value,
                    regex_name,
                    additional_params,
                ) in extract_params_url(event.parsed_url):
                    if self.in_bl(parameter_name) is False:
                        description = f"HTTP Extracted Parameter [{parameter_name}] (Target URL)"
                        data = {
                            "host": parsed_url.hostname,
                            "type": "GETPARAM",
                            "name": parameter_name,
                            "original_value": original_value,
                            "url": self.url_unparse("GETPARAM", parsed_url),
                            "description": description,
                            "additional_params": additional_params,
                        }
                        context = f"Excavate parsed a URL directly from the scan target for parameters and found [GETPARAM] Parameter Name: [{parameter_name}] and emitted a WEB_PARAMETER for it"
                        await self.emit_event(data, "WEB_PARAMETER", event, context=context)

            data = event.data

            # process response data
            body = event.data.get("body", "")
            headers = event.data.get("header-dict", {})
            if body == "" and headers == {}:
                return

            self.assigned_cookies = {}
            content_type = None
            reported_location_header = False

            for header, header_values in headers.items():
                for header_value in header_values:
                    if header.lower() == "set-cookie" and self.parameter_extraction:
                        if "=" not in header_value:
                            self.debug(f"Cookie found without '=': {header_value}")
                            continue
                        else:
                            cookie_name = header_value.split("=")[0]
                            cookie_value = header_value.split("=")[1].split(";")[0]

                            if self.in_bl(cookie_value) is False:
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
                    if header.lower() == "location":
                        redirect_location = getattr(event, "redirect_location", "")
                        if redirect_location:
                            scheme = self.helpers.is_uri(redirect_location, return_scheme=True)
                            if scheme in ("http", "https"):
                                web_spider_distance = getattr(event, "web_spider_distance", 0)
                                num_redirects = max(getattr(event, "num_redirects", 0), web_spider_distance)
                                if num_redirects <= self.scan.web_max_redirects:
                                    # we do not want to allow the web_spider_distance to be incremented on redirects, so we do not add spider-danger tag
                                    url_event = self.make_event(
                                        redirect_location, "URL_UNVERIFIED", event, tags="affiliate"
                                    )
                                    if url_event is not None:
                                        reported_location_header = True
                                        await self.emit_event(
                                            url_event,
                                            context=f'excavate looked in "Location" header and found {url_event.type}: {url_event.data}',
                                        )

                            # Try to extract parameters from the redirect URL
                            if self.parameter_extraction:
                                for (
                                    method,
                                    parsed_url,
                                    parameter_name,
                                    original_value,
                                    regex_name,
                                    additional_params,
                                ) in extract_params_location(header_value, event.parsed_url):
                                    if self.in_bl(parameter_name) is False:
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
                        else:
                            self.warning("location header found but missing redirect_location in HTTP_RESPONSE")
                    if header.lower() == "content-type":
                        content_type = headers["content-type"][0]

            await self.search(
                body,
                event,
                content_type,
                discovery_context="HTTP response (body)",
            )

            if reported_location_header:
                # Location header should be removed if we already found and emitted a result.
                # Failure to do so results in a race against the same URL extracted by the URLExtractor submodule
                # If the extracted URL wins, it will cause the manual one to be a dupe, but it will have a higher web_spider_distance.
                headers.pop("location")
            headers_str = "\n".join(f"{k}: {v}" for k, values in headers.items() for v in values)

            await self.search(
                headers_str,
                event,
                content_type,
                discovery_context="HTTP response (headers)",
            )
        else:
            await self.search(
                event.data,
                event,
                content_type="",
                discovery_context="Parsed file content",
            )

    @classmethod
    def help_text(self):
        # Call the base class help_text method
        base_help_text = super().help_text()

        # Import the current module to inspect its classes
        import sys

        current_module = sys.modules[self.__module__]

        # Function to recursively find subclasses of ExcavateRule
        def find_subclasses(cls):
            subclasses = []
            for name, obj in vars(cls).items():
                if isinstance(obj, type) and issubclass(obj, ExcavateRule) and obj is not ExcavateRule:
                    description = getattr(obj, "description", "No description available.")
                    subclasses.append((name, description))
                # Recursively check for nested classes
                if isinstance(obj, type):
                    subclasses.extend(find_subclasses(obj))
            return subclasses

        # Find all classes in the module that inherit from ExcavateRule
        submodules = find_subclasses(current_module)

        # Format submodules information
        submodules_info = "\nSubmodules:\n"
        if submodules:
            for submodule, description in submodules:
                submodules_info += f"  - {submodule}: {description}\n"
        else:
            submodules_info += "  No submodules available.\n"

        # Combine the base help text with the submodules information
        return base_help_text + submodules_info
