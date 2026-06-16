import yara
import json
import html
import time
import inspect
import regex as re
from pathlib import Path
from bbot.errors import ExcavateError, ValidationError
import bbot.core.helpers.regexes as bbot_regexes
from bbot.modules.base import BaseInterceptModule
from bbot.modules.internal.base import BaseInternalModule
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urldefrag
from bbot.core.config.models import BaseModuleConfig, Field


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


def _pick_select_value(options_html):
    """Choose the best <option> value from a <select>'s inner HTML.

    Preference order:
      1. The option carrying a `selected` attribute (its value, blank or not).
      2. The first option's value (blank or not) — filter-style forms often use
         an empty default that "matches all", so substituting a specific choice
         could narrow results to nothing.
      3. None, if there are no options at all.
    """
    if not options_html:
        return None
    selected_value = None
    selected_found = False
    first_value = None
    first_set = False
    for attrs in bbot_regexes.option_tag_regex.findall(options_html):
        value_match = bbot_regexes.option_value_regex.search(attrs)
        if value_match:
            value = next((g for g in value_match.groups() if g is not None), "")
        else:
            value = ""
        if not first_set:
            first_value = value
            first_set = True
        if not selected_found and bbot_regexes.option_selected_regex.search(attrs):
            selected_value = value
            selected_found = True
    if selected_found:
        return selected_value
    return first_value if first_set else None


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
    """
    Yields query parameters from a parsed URL.

    Args:
        parsed_url (ParseResult): The URL to extract parameters from.

    Yields:
        tuple: Contains the hardcoded HTTP method ('GET'), parsed URL, parameter name,
               original value, source (hardcoded to 'direct_url'), and additional parameters
               (all parameters excluding the current one).
    """
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
    def __init__(self, description, tags, emit_match, severity, confidence):
        self.description = description
        self.tags = tags
        self.emit_match = emit_match
        self.severity = severity
        self.confidence = confidence


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
        severity = "INFO"
        confidence = "UNKNOWN"

        if "description" in r.meta.keys():
            description = r.meta["description"]
        if "tags" in r.meta.keys():
            tags = self.excavate.helpers.chain_lists(r.meta["tags"])
        if "emit_match" in r.meta.keys():
            emit_match = True
        if "severity" in r.meta.keys():
            severity = r.meta["severity"]
        if "confidence" in r.meta.keys():
            confidence = r.meta["confidence"]

        yara_rule_settings = YaraRuleSettings(description, tags, emit_match, severity, confidence)
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
            The settings configured from YARA rule meta tags, including description, severity, confidence, tags, and emit_match flag.
        discovery_context : DiscoveryContext
            The context in which the discovery is made.

        Returns:
        None
        """
        for results in yara_results.values():
            for result in results:
                event_data = {
                    "name": f"{discovery_context} {yara_rule_settings.description}",
                    "description": f"{discovery_context} {yara_rule_settings.description}",
                }
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
            The settings configured from YARA rule meta tags, including description, severity, confidence, and tags.
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
        if event_type == "URL_UNVERIFIED" and await self.excavate._host_is_http_wildcard(event):
            return

        # If a description is not set and is needed, provide a basic one
        if event_type == "FINDING":
            if "description" not in event_data.keys():
                event_data["description"] = f"{discovery_context} {yara_rule_settings.description}"
            if "name" not in event_data.keys():
                event_data["name"] = f"{discovery_context} {yara_rule_settings.description}"
            if "severity" not in event_data.keys():
                event_data["severity"] = yara_rule_settings.severity
            if "confidence" not in event_data.keys():
                event_data["confidence"] = yara_rule_settings.confidence
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
                event_data = {
                    "name": f"Custom Yara Rule [{self.name}]",
                }
                description_string = (
                    f" with description: [{yara_rule_settings.description}]" if yara_rule_settings.description else ""
                )
                event_data["description"] = (
                    f"Custom Yara Rule [{self.name}]{description_string} Matched via identifier [{identifier}]"
                )
                if yara_rule_settings.emit_match:
                    event_data["description"] += f" and extracted [{result}]"
                event_data["severity"] = yara_rule_settings.get("severity", "LOW")
                event_data["confidence"] = yara_rule_settings.get("confidence", "UNKNOWN")

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
    _avoid_duplicate_content = True
    flags = ["safe", "passive"]
    meta = {
        "description": "Passively extract juicy tidbits from scan data",
        "created_date": "2022-06-27",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        yara_max_match_data: int = Field(
            2000, description="Sets the maximum amount of text that can extracted from a YARA regex"
        )
        custom_yara_rules: str = Field("", description="Include custom Yara rules")
        speculate_params: bool = Field(
            False, description="Enable speculative parameter extraction from JSON and XML content"
        )
        max_form_bytes: int = Field(
            262144,
            description="Maximum byte slice of the response body searched for a single <form> body. YARA only locates form openings; the bounded slice is what the Python re-based extractor scans for fields. Caps worst-case extraction work per form match.",
        )

    scope_distance_modifier = None
    accept_dupes = False

    _module_threads = 6

    yara_rule_name_regex = re.compile(r"rule\s(\w+)\s{")
    yara_rule_regex = re.compile(r"(?s)((?:rule\s+\w+\s*{[^{}]*(?:{[^{}]*}[^{}]*)*[^{}]*(?:/\S*?}[^/]*?/)*)*})")

    def in_bl(self, value):
        # Check if the value is in the blacklist or starts with a blacklisted prefix.
        lower_value = value.lower()

        if lower_value in self.parameter_blacklist:
            return True

        for bl_param_prefix in self.parameter_blacklist_prefixes:
            if lower_value.startswith(bl_param_prefix):
                return True

        return False

    def _is_archived(self, event):
        """Check if an event represents archived wayback content."""
        return isinstance(event.data, dict) and "archive_url" in event.data

    async def _host_is_http_wildcard(self, event):
        """True if this event's host is an HTTP wildcard responder."""
        return await self._is_http_wildcard_host(event) is True

    def _event_host(self, event):
        """Get the effective host from an event.

        For archived wayback content, uses data["host"] (the original target hostname).
        For regular events, uses event.host.

        NOTE: Regular HTTP_RESPONSE events also have data["host"], but it contains the
        resolved IP — NOT a hostname override.
        """
        if self._is_archived(event) and event.data.get("host"):
            return str(event.data["host"])
        return str(event.host)

    def _event_base_url(self, event):
        """Get the effective base URL from an event.

        For archived wayback content, reconstructs the URL from explicit fields
        (host/scheme/port/path). For regular events, returns event.parsed_url directly.
        """
        if not self._is_archived(event):
            return event.parsed_url
        scheme = event.data.get("scheme", event.parsed_url.scheme)
        host = self._event_host(event)
        port = event.data.get("port")
        if port is not None:
            port = int(port)
            if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                host = f"{host}:{port}"
        path = event.data.get("path", event.parsed_url.path)
        return urlparse(f"{scheme}://{host}{path}")

    def url_unparse(self, param_type, parsed_url):
        # Reconstructs a URL, optionally omitting the query string based on remove_querystring configuration value.
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
                "" if self.remove_querystring else querystring,
                "",
            )
        )

    class ParameterExtractor(ExcavateRule):
        description = "Extracts web parameters. Enabled if any modules are enabled that emit WEB_PARAMETER events."
        yara_rules = {}

        class ParameterExtractorRule:
            name = ""

            async def extract(self):
                pass

            def __init__(self, excavate, result, response_body=None, match_offset=0):
                self.excavate = excavate
                self.result = result
                self.response_body = response_body
                self.match_offset = match_offset

            def form_body_slice(self):
                """Return up to ``max_form_bytes`` of response body starting at the YARA match offset.

                YARA only locates form openings (its ~4 KB `.*` ceiling can't span large forms);
                the Python extraction regex runs on this slice. Forms exceeding the cap are skipped.
                """
                if not self.response_body:
                    return str(self.result)
                max_bytes = getattr(self.excavate, "max_form_bytes", 262144)
                body_bytes = self.response_body.encode("utf-8", errors="replace")
                end = min(len(body_bytes), self.match_offset + max_bytes)
                return body_bytes[self.match_offset : end].decode("utf-8", errors="replace")

        class GetJquery(ParameterExtractorRule):
            name = "GET jquery"
            discovery_regex = r"/\$.get\([^\)].+\)/ nocase"
            extraction_regex = re.compile(r"\$.get\([\'\"](.+)[\'\"].+(\{.+\})\)")
            _json_key_regex = re.compile(r"(\w+):")
            output_type = "GETPARAM"

            async def extract(self):
                extracted_results = await self.excavate.helpers.re.findall(self.extraction_regex, str(self.result))
                if extracted_results:
                    for action, extracted_parameters in extracted_results:
                        extracted_parameters_dict = await self.convert_to_dict(extracted_parameters)
                        if extracted_parameters_dict is None:
                            continue
                        for parameter_name, original_value in extracted_parameters_dict.items():
                            yield (
                                self.output_type,
                                parameter_name,
                                original_value.strip(),
                                action,
                                _exclude_key(extracted_parameters_dict, parameter_name),
                            )

            async def convert_to_dict(self, extracted_str):
                extracted_str = extracted_str.replace("'", '"')
                extracted_str = await self.excavate.helpers.re.sub(
                    self._json_key_regex, r'"\1":', extracted_str
                )  # Quote keys

                try:
                    return json.loads(extracted_str)
                except json.JSONDecodeError as e:
                    self.excavate.debug(f"Failed to decode JSON: {e}")
                    return None

        class PostJquery(GetJquery):
            name = "POST jquery"
            discovery_regex = r"/\$.post\([^\)].+\)/ nocase"
            extraction_regex = re.compile(r"\$.post\([\'\"](.+)[\'\"].+(\{.+\})\)")
            output_type = "POSTPARAM"

        class HtmlTags(ParameterExtractorRule):
            name = "HTML Tags"
            discovery_regex = r'/<[^>]+(href|src|action)=["\']?[^"\'>\s]*["\']?[^>]*>/ nocase'
            extraction_regex = bbot_regexes.tag_attribute_regex
            output_type = "GETPARAM"

            async def extract(self):
                urls = await self.excavate.helpers.re.findall(self.extraction_regex, str(self.result))
                for url in urls:
                    parsed_url = urlparse(url)
                    query_strings = parse_qs(html.unescape(parsed_url.query))
                    query_strings_dict = {k: v[0] if isinstance(v, list) else v for k, v in query_strings.items()}
                    for parameter_name, original_value in query_strings_dict.items():
                        yield (
                            self.output_type,
                            parameter_name,
                            original_value.strip(),
                            url,
                            _exclude_key(query_strings_dict, parameter_name),
                        )

        class AjaxJquery(ParameterExtractorRule):
            name = "JQuery Extractor"
            discovery_regex = r"/\$\.ajax\(\{[^\<$\$]*\}\)/s nocase"
            extraction_regex = None
            output_type = "BODYJSON"
            ajax_content_regexes = {
                "url": re.compile(r"url\s*:\s*['\"](.*?)['\"]"),
                "type": re.compile(r"type\s*:\s*['\"](.*?)['\"]"),
                "content_type": re.compile(r"contentType\s*:\s*['\"](.*?)['\"]"),
                "data": re.compile(r"data:.*(\{[^}]*\})"),
            }

            async def extract(self):
                # Iterate through each regex in ajax_content_regexes
                extracted_values = {}
                for key, pattern in self.ajax_content_regexes.items():
                    match = await self.excavate.helpers.re.search(pattern, self.result)
                    if match:
                        # Store the matched value in the dictionary
                        extracted_values[key] = match.group(1)

                # Check to see if the format is defined as JSON
                if (
                    "content_type" in extracted_values.keys()
                    and extracted_values["content_type"] == "application/json"
                ):
                    form_parameters = {}

                    # If we can't figure out the parameter names, there is no point in continuing
                    if "data" in extracted_values.keys():
                        form_url = extracted_values.get("url", None)

                        try:
                            s = extracted_values["data"]
                            s = await self.excavate.helpers.re.sub(re.compile(r"(\w+)\s*:"), r'"\1":', s)  # Quote keys
                            s = await self.excavate.helpers.re.sub(
                                re.compile(r":\s*(\w+)"), r': "\1"', s
                            )  # Quote values if they are unquoted
                            data = json.loads(s)
                        except (ValueError, SyntaxError):
                            data = None

                        if data:
                            for p in data.keys():
                                form_parameters[p] = None

                    for parameter_name in form_parameters:
                        yield (
                            "BODYJSON",
                            parameter_name,
                            None,
                            form_url,
                            _exclude_key(form_parameters, parameter_name),
                        )

        class GetForm(ParameterExtractorRule):
            name = "GET Form"
            # YARA matches only the opening tag; extract() scans a bounded body slice (form_body_slice).
            discovery_regex = r'/<form[^>]*\bmethod=["\']?get["\']?[^>]*>/s nocase'
            form_content_regexes = {
                "input_tag_regex": bbot_regexes.input_tag_regex,
                "input_tag_regex2": bbot_regexes.input_tag_regex2,
                "select_tag_regex": bbot_regexes.select_tag_regex,
                "textarea_tag_regex": bbot_regexes.textarea_tag_regex,
                "textarea_tag_regex2": bbot_regexes.textarea_tag_regex2,
                "textarea_tag_novalue_regex": bbot_regexes.textarea_tag_novalue_regex,
                "button_tag_regex": bbot_regexes.button_tag_regex,
                "button_tag_regex2": bbot_regexes.button_tag_regex2,
                "_input_tag_novalue_regex": bbot_regexes.input_tag_novalue_regex,
            }
            extraction_regex = bbot_regexes.get_form_regex
            output_type = "GETPARAM"

            async def extract(self):
                forms = await self.excavate.helpers.re.findall(self.extraction_regex, self.form_body_slice())
                for form_action, form_content in forms:
                    if not form_action or form_action == "#":
                        form_action = None

                    elif form_action.startswith("./"):
                        form_action = form_action.lstrip(".")

                    form_parameters = {}
                    for form_content_regex_name, form_content_regex in self.form_content_regexes.items():
                        input_tags = await self.excavate.helpers.re.findall(form_content_regex, form_content)
                        if input_tags:
                            # Normalize each input_tag to be a tuple of two elements
                            input_tags = [(tag if isinstance(tag, tuple) else (tag, None)) for tag in input_tags]

                            if form_content_regex_name in [
                                "input_tag_regex2",
                                "button_tag_regex2",
                                "textarea_tag_regex2",
                            ]:
                                # Swap elements if needed
                                input_tags = [(b, a) for a, b in input_tags]
                            if form_content_regex_name == "select_tag_regex":
                                # Prefer the option marked `selected`, falling back to the first
                                # option (blank or not — filter forms often use a blank default
                                # that matches all results)
                                input_tags = [
                                    (name, _pick_select_value(options_html)) for name, options_html in input_tags
                                ]
                            for parameter_name, original_value in input_tags:
                                # Preserve empty strings; only None means "no value seen".
                                normalized = original_value.strip() if original_value is not None else None
                                form_parameters.setdefault(parameter_name, normalized)

                    for parameter_name, original_value in form_parameters.items():
                        yield (
                            self.output_type,
                            parameter_name,
                            original_value,
                            form_action,
                            _exclude_key(form_parameters, parameter_name),
                        )

        class GetForm2(GetForm):
            extraction_regex = bbot_regexes.get_form_regex2

        class PostForm(GetForm):
            name = "POST Form"
            discovery_regex = r'/<form[^>]*\bmethod=["\']?post["\']?[^>]*>/s nocase'
            extraction_regex = bbot_regexes.post_form_regex
            output_type = "POSTPARAM"

        class PostForm2(PostForm):
            extraction_regex = bbot_regexes.post_form_regex2

        class PostForm_NoAction(PostForm):
            name = "POST Form (no action)"
            extraction_regex = bbot_regexes.post_form_regex_noaction

        # underscore ensure generic forms runs last, so it doesn't cause dedupe to stop full form detection
        class _GenericForm(GetForm):
            name = "Generic Form"
            discovery_regex = r"/<form[^>]*>/s nocase"

            extraction_regex = bbot_regexes.generic_form_regex
            output_type = "GETPARAM"

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
                rf'rule parameter_extraction {{meta: description = "contains Parameter" strings: {regexes_component} condition: any of them}}'
            )

        async def preprocess(self, r, event, discovery_context):
            # Override base flattener to retain per-instance YARA offsets (needed by form_body_slice).
            description = ""
            tags = []
            emit_match = False
            severity = "INFO"
            confidence = "UNKNOWN"
            if "description" in r.meta.keys():
                description = r.meta["description"]
            if "tags" in r.meta.keys():
                tags = self.excavate.helpers.chain_lists(r.meta["tags"])
            if "emit_match" in r.meta.keys():
                emit_match = True
            if "severity" in r.meta.keys():
                severity = r.meta["severity"]
            if "confidence" in r.meta.keys():
                confidence = r.meta["confidence"]
            yara_rule_settings = YaraRuleSettings(description, tags, emit_match, severity, confidence)

            yara_results = {}
            for h in r.strings:
                instances = []
                seen_offsets = set()
                for i in h.instances:
                    offset = getattr(i, "offset", 0)
                    if offset in seen_offsets:
                        continue
                    seen_offsets.add(offset)
                    instances.append((i.matched_data.decode("utf-8", errors="ignore"), offset))
                yara_results[h.identifier.lstrip("$")] = instances
            await self.process(yara_results, event, yara_rule_settings, discovery_context)

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            # Group yields by (type, name, url) within an identifier; extra distinct values for
            # the same param are stashed in same_param_values so they survive WEB_PARAMETER dedup.
            # Use event.body (property) so we hit the body-spill store; event.data["body"] is
            # popped at spill time and would be empty here.
            response_body = getattr(event, "body", "") or ""
            for identifier, results in yara_results.items():
                if identifier not in self.parameterExtractorCallbackDict.keys():
                    raise ExcavateError("ParameterExtractor YaraRule identified reference non-existent submodule")
                grouped = {}
                submodule_name = None
                for matched_data, match_offset in results:
                    parameterExtractorSubModule = self.parameterExtractorCallbackDict[identifier](
                        self.excavate,
                        matched_data,
                        response_body=response_body,
                        match_offset=match_offset,
                    )
                    submodule_name = parameterExtractorSubModule.name
                    async for (
                        parameter_type,
                        parameter_name,
                        original_value,
                        endpoint,
                        additional_params,
                    ) in parameterExtractorSubModule.extract():
                        self.excavate.debug(
                            f"Found Parameter [{parameter_name}] in [{submodule_name}] ParameterExtractor Submodule"
                        )

                        # account for the case where the action is html encoded
                        if endpoint and (
                            endpoint.startswith("https&#x3a;&#x2f;&#x2f;")
                            or endpoint.startswith("http&#x3a;&#x2f;&#x2f;")
                        ):
                            endpoint = html.unescape(endpoint)

                        # If we have a full URL, leave it as-is
                        if endpoint and endpoint.startswith(("http://", "https://")):
                            url = endpoint

                        # The endpoint is usually a form action - we should use it if we have it. If not, default to URL.
                        else:
                            # Use the effective base URL (which may differ from parsed_url for archived content)
                            event_base = self.excavate._event_base_url(event)
                            base_url = f"{event_base.scheme}://{event_base.netloc}{event_base.path}"
                            if not self.excavate.remove_querystring and len(event.parsed_url.query) > 0:
                                base_url += f"?{event.parsed_url.query}"
                            url = urljoin(base_url, endpoint)

                        try:
                            # Validate the URL before using it
                            parsed_url = self.excavate.helpers.validators.validate_url_parsed(url)
                        except (ValidationError, ValueError) as e:
                            self.excavate.debug(f"Invalid URL [{url}]: {e}")
                            continue

                        if not self.excavate.helpers.validate_parameter(parameter_name, parameter_type):
                            self.excavate.debug(f"blocked parameter [{parameter_name}] due to validation failure")
                            continue
                        if self.excavate.in_bl(parameter_name) is not False:
                            self.excavate.debug(f"blocked parameter [{parameter_name}] due to BL match")
                            continue

                        emit_url = self.excavate.url_unparse(parameter_type, parsed_url)
                        group_key = (parameter_type, parameter_name, emit_url)
                        if group_key not in grouped:
                            grouped[group_key] = {
                                "parsed_url": parsed_url,
                                "values": [],
                                "additional_params": additional_params,
                            }
                        group_values = grouped[group_key]["values"]
                        if original_value not in group_values:
                            group_values.append(original_value)

                for (parameter_type, parameter_name, emit_url), group in grouped.items():
                    values = group["values"]
                    primary_value = values[0]
                    same_param_values = values[1:]
                    description = f"HTTP Extracted Parameter [{parameter_name}] ({submodule_name} Submodule)"
                    data = {
                        "host": group["parsed_url"].hostname,
                        "type": parameter_type,
                        "name": parameter_name,
                        "original_value": primary_value,
                        "url": emit_url,
                        "additional_params": group["additional_params"],
                        "assigned_cookies": self.excavate.assigned_cookies,
                        "description": description,
                    }
                    if same_param_values:
                        data["same_param_values"] = same_param_values
                    # Stamp the discovery page URL when distinct from the form's action.
                    # Downstream fuzzers use it for cookie/CSRF priming and as the Referer.
                    host_url = event.url
                    if host_url and host_url != emit_url:
                        data["host_url"] = host_url
                    await self.report(data, event, yara_rule_settings, discovery_context, event_type="WEB_PARAMETER")

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
            "jwt": r'rule jwt { meta: emit_match = "True" description = "contains JSON Web Token (JWT)" confidence = "CONFIRMED" strings: $jwt = /\beyJ[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*\.[_a-zA-Z0-9\/+]*/ nocase condition: $jwt }',
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
                f'rule error_detection {{meta: description = "contains a verbose error message" severity = "INFO" confidence = "MEDIUM" strings: {signature_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "name": "Possible Verbose Error Message",
                        "description": f"{discovery_context} {yara_rule_settings.description} ({identifier})",
                    }
                    await self.report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING")

    class SerializationExtractor(ExcavateRule):
        description = "Identifies serialized objects from various platforms."
        regexes = {
            "Java": re.compile(r"[^a-zA-Z0-9\/+][\"']?rO0[a-zA-Z0-9+\/]+={0,2}"),
            "Ruby": re.compile(r"[^a-zA-Z0-9\/+][\"']?BAh[a-zA-Z0-9+\/]+={0,2}"),
            "DOTNET": re.compile(r"[^a-zA-Z0-9\/+][\"']?AAEAAAD\/\/[a-zA-Z0-9\/+]+={0,2}"),
            "PHP_Array": re.compile(r"[^a-zA-Z0-9\/+][\"']?YTo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "PHP_String": re.compile(r"[^a-zA-Z0-9\/+][\"']?czo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "PHP_Object": re.compile(r"[^a-zA-Z0-9\/+][\"']?Tzo[xyz0123456][a-zA-Z0-9+\/]+={0,2}"),
            "Possible_Compressed": re.compile(r"[^a-zA-Z0-9\/+][\"']?H4sIAAAA[a-zA-Z0-9+\/]+={0,2}"),
        }
        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            regexes_component_list = []
            for regex_name, regex in self.regexes.items():
                regexes_component_list.append(rf"${regex_name} = /\b{regex.pattern}/")
            regexes_component = " ".join(regexes_component_list)
            self.yara_rules["serialization_detection"] = (
                f'rule serialization_detection {{meta: description = "contains a possible serialized object" severity = "INFO" confidence = "MEDIUM" strings: {regexes_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "name": "Possible Serialized Object",
                        "description": f"{discovery_context} {yara_rule_settings.description} ({identifier})",
                    }
                    await self.report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING")

    class FunctionalityExtractor(ExcavateRule):
        description = "Detects potentially exploitable functionality and attack surface in web applications."
        yara_rules = {
            "File_Upload_Functionality": r'rule File_Upload_Functionality { meta: description = "contains file upload functionality" confidence = "CONFIRMED" strings: $fileuploadfunc = /<input[^>]+type=["\']?file["\']?[^>]+>/ nocase condition: $fileuploadfunc }',
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
                    # convert websocket URLs to their HTTP equivalents
                    if parsed_url.scheme in ["ws", "wss"]:
                        http_scheme = "https" if parsed_url.scheme == "wss" else "http"
                        http_url = parsed_url._replace(scheme=http_scheme).geturl()
                        await self.report(
                            http_url,
                            event,
                            yara_rule_settings,
                            discovery_context,
                            event_type="URL_UNVERIFIED",
                        )
                        continue

                    if parsed_url.scheme in ["http", "https"]:
                        continue

                    def abort_if(e):
                        return e.scope_distance > 0

                    finding_data = {
                        "host": str(host),
                        "name": "Non-HTTP URI",
                        "description": f"Non-HTTP URI: {parsed_url.geturl()}",
                    }
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
                        $url_full = /https?:\/\/(\[[0-9a-fA-F:]+\]|[\w\.-]+)(:\d{1,5})?([\/\w\.-]*)/
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
                        $url_attr = /<[^>]+(href|src|action)=["\']?[^"\']*["\']?[^>]*>/
                    condition:
                        $url_attr
                }
                """
            ),
        }
        full_url_regex = re.compile(
            r"(https?)://((?:\[[0-9a-fA-F:]+\]|\w(?:[\w-]+\.?)+)(?::\d{1,5})?(?:/[-\w\.\(\)]*[-\w\.]+)*/?)"
        )
        full_url_regex_strict = re.compile(
            r"^(https?):\/\/(\[[0-9a-fA-F:]+\]|[\w.-]+)(?::\d{1,5})?(\/[\w\/\.-]*)?(\?[^\s]+)?$"
        )
        tag_attribute_regex = bbot_regexes.tag_attribute_regex

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier, results in yara_results.items():
                urls_found = 0
                final_url = ""
                for url_str in results:
                    try:
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
                            # Validate the URL before using it
                            self.excavate.helpers.validators.validate_url_parsed(final_url)
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
                    except (ValidationError, ValueError) as e:
                        self.excavate.debug(f"Invalid URL [{url_str if not final_url else final_url}]: {e}")
                        continue

        async def report_prep(self, event_data, event_type, event, tags, **kwargs):
            event_draft = self.excavate.make_event(event_data, event_type, parent=event)
            if not event_draft:
                return None
            url_in_scope = self.excavate.scan.in_scope(event_draft.host_filterable)
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

    class DirectoryListingExtractor(ExcavateRule):
        description = "Detects directory listing pages from web servers."
        signatures = {
            "Apache_Nginx": '"<title>Index of /"',
            "IIS": '"[To Parent Directory]"',
            "Python_HTTP_Server": '"<h1>Directory listing for"',
            "Generic_Directory_Listing": '"<title>Directory Listing"',
        }
        yara_rules = {}

        def __init__(self, excavate):
            super().__init__(excavate)
            signature_component_list = []
            for signature_name, signature in self.signatures.items():
                signature_component_list.append(rf"${signature_name} = {signature}")
            signature_component = " ".join(signature_component_list)
            self.yara_rules["directory_listing"] = (
                f'rule directory_listing {{meta: description = "contains a directory listing" strings: {signature_component} condition: any of them}}'
            )

        async def process(self, yara_results, event, yara_rule_settings, discovery_context):
            for identifier in yara_results.keys():
                for findings in yara_results[identifier]:
                    event_data = {
                        "description": f"{discovery_context} {yara_rule_settings.description} ({identifier})"
                    }
                    await self.report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING")

    def add_yara_rule(self, rule_name, rule_content, rule_instance):
        rule_instance.name = rule_name
        self.yara_rules_dict[rule_name] = rule_content
        self.yara_preprocess_dict[rule_name] = rule_instance.preprocess

    async def extract_yara_rules(self, rules_content):
        for r in await self.helpers.re.findall(self.yara_rule_regex, rules_content):
            yield r

    async def emit_web_parameter(
        self, host, param_type, name, original_value, url, description, additional_params, event, context
    ):
        data = {
            "host": host,
            "type": param_type,
            "name": name,
            "original_value": original_value,
            "url": url,
            "description": description,
            "additional_params": additional_params,
        }
        await self.emit_event(data, "WEB_PARAMETER", event, context=context)

    async def emit_custom_parameters(self, event, config_key, param_type, description_suffix):
        # Emits WEB_PARAMETER events for custom headers and cookies from the configuration.
        custom_params = self.scan.web_config.get(config_key, {})
        for param_name, param_value in custom_params.items():
            event_base = self._event_base_url(event)
            await self.emit_web_parameter(
                host=self._event_host(event),
                param_type=param_type,
                name=param_name,
                original_value=param_value,
                url=self.url_unparse(param_type, event_base),
                description=f"HTTP Extracted Parameter [{param_name}] ({description_suffix})",
                additional_params=_exclude_key(custom_params, param_name),
                event=event,
                context=f"Excavate saw a custom {param_type.lower()} set [{param_name}], and emitted a WEB_PARAMETER for it",
            )

    async def setup(self):
        self.yara_rules_dict = {}
        self.yara_preprocess_dict = {}

        modules_WEB_PARAMETER = [
            module_name
            for module_name, module in self.scan.modules.items()
            if "WEB_PARAMETER" in module.watched_events
        ]

        self.parameter_extraction = bool(modules_WEB_PARAMETER)
        self.speculate_params = self.config.get("speculate_params", False)
        self.remove_querystring = self.scan.config.get("url_querystring_remove", True)
        # Bounded slice of the response body searched for a form's body, anchored
        # at each YARA form-opening match. Caps worst-case Python re work per form.
        self.max_form_bytes = int(self.config.get("max_form_bytes", 262144))

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

        self.parameter_blacklist = set(p.lower() for p in self.scan.config.get("parameter_blacklist", []))
        self.parameter_blacklist_prefixes = set(
            p.lower() for p in self.scan.config.get("parameter_blacklist_prefixes", [])
        )

        self.custom_yara_rules = self.config.get("custom_yara_rules", "")
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

        if self.parameter_extraction and self.speculate_params:
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
                            await self.emit_web_parameter(
                                host=self._event_host(event),
                                param_type="SPECULATIVE",
                                name=parameter_name,
                                original_value=original_value,
                                url=event.url,
                                description=f"HTTP Extracted Parameter (speculative from {source_type} content) [{parameter_name}]",
                                additional_params={},
                                event=event,
                                context=f"excavate's Parameter extractor found a speculative WEB_PARAMETER: {parameter_name} by parsing {source_type} data from {self._event_host(event)}",
                            )
                    return

        # Initialize the list of data items to process
        data_items = []

        # Check if data and decoded_data are identical
        if data == decoded_data:
            data_items.append(("data", data))  # Add only one since both are the same
        else:
            data_items.append(("data", data))
            data_items.append(("decoded_data", decoded_data))

        for label, data_instance in data_items:
            # Your existing processing code
            for result in await self.helpers.run_in_executor_cpu(self.yara_rules.match, data=f"{data_instance}"):
                rule_name = result.rule

                # Skip specific operations for 'parameter_extraction' rule on decoded_data
                if label == "decoded_data" and rule_name == "parameter_extraction":
                    continue

                # Check if rule processing function exists
                if rule_name in self.yara_preprocess_dict:
                    try:
                        await self.yara_preprocess_dict[rule_name](result, event, discovery_context)
                    except ValidationError as e:
                        self.debug(f"ValidationError in rule {rule_name} for result {result}: {e}")
                else:
                    self.hugewarning(f"YARA Rule {rule_name} not found in pre-compiled rules")

    async def handle_event(self, event, **kwargs):
        if event.type == "HTTP_RESPONSE":
            if self.parameter_extraction is True:
                # if parameter extraction is enabled, and we have custom cookies or headers, emit them as WEB_PARAMETER events
                await self.emit_custom_parameters(event, "http_cookies", "COOKIE", "Custom Cookie")
                await self.emit_custom_parameters(event, "http_headers", "HEADER", "Custom Header")

                # if parameter extraction is enabled, and querystring removal is disabled, and the event is directly from the SEED, create a WEB
                if self.url_querystring_remove is False and str(event.parent.parent.module) == "SEED":
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
                            await self.emit_web_parameter(
                                host=self._event_host(event),
                                param_type="GETPARAM",
                                name=parameter_name,
                                original_value=original_value,
                                url=self.url_unparse("GETPARAM", parsed_url),
                                description=f"HTTP Extracted Parameter [{parameter_name}] (Target URL)",
                                additional_params=additional_params,
                                event=event,
                                context=f"Excavate parsed a URL directly from the scan target for parameters and found [GETPARAM] Parameter Name: [{parameter_name}] and emitted a WEB_PARAMETER for it",
                            )

            # process response data
            body = event.body
            headers = event.data.get("header-dict", {})
            if body == "" and headers == {}:
                return

            self.assigned_cookies = {}
            content_type = None
            reported_location_header = False

            for header, header_values in headers.items():
                for header_value in header_values:
                    # Process 'set-cookie' headers to extract and emit cookies as WEB_PARAMETER events.
                    if header.lower() == "set-cookie" and self.parameter_extraction:
                        if "=" not in header_value:
                            self.debug(f"Cookie found without '=': {header_value}")
                            continue
                        else:
                            cookie_name, _, remainder = header_value.partition("=")
                            cookie_value = remainder.split(";")[0]

                            if self.in_bl(cookie_name) is False:
                                self.assigned_cookies[cookie_name] = cookie_value
                                event_base = self._event_base_url(event)
                                await self.emit_web_parameter(
                                    host=self._event_host(event),
                                    param_type="COOKIE",
                                    name=cookie_name,
                                    original_value=cookie_value,
                                    url=self.url_unparse("COOKIE", event_base),
                                    description=f"Set-Cookie Assigned Cookie [{cookie_name}]",
                                    additional_params={},
                                    event=event,
                                    context=f"Excavate noticed a set-cookie header for cookie [{cookie_name}] and emitted a WEB_PARAMETER for it",
                                )
                            else:
                                self.debug(f"blocked cookie parameter [{cookie_name}] due to BL match")
                    # Handle 'location' headers to process and emit redirect URLs as URL_UNVERIFIED events.
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
                                            context=f'excavate looked in "Location" header and found {url_event.type}: {url_event.url}',
                                        )

                            # Try to extract parameters from the redirect URL
                            if self.parameter_extraction:
                                # Don't extract parameters from out-of-scope redirects --
                                # they would inherit in-scope status from the parent event
                                # and cause lightfuzz to fuzz external endpoints
                                redirect_parsed = urlparse(redirect_location)
                                redirect_host = redirect_parsed.hostname
                                if redirect_host and not self.scan.in_scope(redirect_host):
                                    self.debug(
                                        f"Skipping parameter extraction from out-of-scope redirect to {redirect_host}"
                                    )
                                else:
                                    for (
                                        method,
                                        parsed_url,
                                        parameter_name,
                                        original_value,
                                        regex_name,
                                        additional_params,
                                    ) in extract_params_location(header_value, self._event_base_url(event)):
                                        if self.in_bl(parameter_name) is False:
                                            await self.emit_web_parameter(
                                                host=self._event_host(event),
                                                param_type="GETPARAM",
                                                name=parameter_name,
                                                original_value=original_value,
                                                url=self.url_unparse("GETPARAM", parsed_url),
                                                description=f"HTTP Extracted Parameter [{parameter_name}] (Location Header)",
                                                additional_params=additional_params,
                                                event=event,
                                                context=f"Excavate parsed a location header for parameters and found [GETPARAM] Parameter Name: [{parameter_name}] and emitted a WEB_PARAMETER for it",
                                            )
                        else:
                            self.warning("location header found but missing redirect_location in HTTP_RESPONSE")
                    if header.lower() == "content-type":
                        content_type = headers["content-type"][0]

            # skip PDF responses -- running YARA/regex on raw PDF bytes produces false positives and wastes time.
            # PDFs are still processed correctly via the filedownload → kreuzberg → RAW_TEXT pipeline,
            # which extracts readable text and feeds it back to excavate as a RAW_TEXT event (handled separately below).
            # TODO: remove this in favor of a proper categorization system for text vs non-text (i.e. to-be-extracted) content
            if content_type and "application/pdf" in content_type.lower():
                self.debug(f"Skipping PDF response: {event.url or 'unknown'}")
                return

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
