import copy
import base64
import binascii
from urllib.parse import quote


class BaseLightfuzz:
    friendly_name = ""
    uses_interactsh = False
    # True for submodules whose payloads ARE the wire format (e.g. `serial`) — skip envelope wrapping.
    skip_envelopes = False

    def __init__(self, lightfuzz, event):
        self.lightfuzz = lightfuzz
        self.event = event
        self.results = []
        self.parameter_name = self.event.data["name"]

    def register_interactsh_tag(
        self, *, name, description, severity, confidence, severity_dns=None, confidence_dns=None
    ):
        """Register a fresh interactsh subdomain tag and return `(tag, host)`.

        Caller incorporates ``host`` into its payload, then sends via
        ``self.standard_probe`` (or equivalent). ``severity_dns`` and
        ``confidence_dns`` optionally override the emitted finding's
        severity/confidence when the observed interaction is DNS-only.
        """
        tag = self.lightfuzz.helpers.rand_string(4, digits=False)
        details = {
            "event": self.event,
            "name": name,
            "description": description,
            "severity": severity,
            "confidence": confidence,
        }
        if severity_dns is not None:
            details["severity_dns"] = severity_dns
        if confidence_dns is not None:
            details["confidence_dns"] = confidence_dns
        self.lightfuzz.interactsh_subdomain_tags[tag] = details
        return tag, f"{tag}.{self.lightfuzz.interactsh_domain}"

    @staticmethod
    def is_hex(s):
        try:
            bytes.fromhex(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_base64(s):
        try:
            if base64.b64encode(base64.b64decode(s)).decode() == s:
                return True
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        return False

    # WEB_PARAMETER event may contain additional_params (e.g. other parameters in the same form or query string). These will be sent unchanged along with the probe.
    def additional_params_process(self, additional_params, additional_params_populate_empty):
        """
        Processes additional parameters by populating blank or empty values with random strings if specified.

        Parameters:
        - additional_params (dict): A dictionary of additional parameters to process.
        - additional_params_populate_blank_empty (bool): If True, populates blank or empty parameter values with random numeric strings.

        Returns:
        - dict: A dictionary with processed additional parameters, where blank or empty values are replaced with random strings if specified.

        The function iterates over the provided additional parameters and replaces any blank or empty values with a random numeric string
        of length 10, if the flag is set to True. Otherwise, it returns the parameters unchanged.
        """
        if not additional_params or not additional_params_populate_empty:
            return additional_params

        return {
            k: self.lightfuzz.helpers.rand_string(10, numeric_only=True) if v in ("", None) else v
            for k, v in additional_params.items()
        }

    def conditional_urlencode(self, probe, event_type, skip_urlencoding=False):
        """Conditionally url-encodes the probe if the event type requires it and encoding is not skipped by the submodule.
        We also don't encode if any envelopes are present.
        """
        if event_type in ["GETPARAM", "COOKIE"] and not skip_urlencoding and getattr(self.event, "envelopes", None):
            # Exclude '&' from being encoded since we are operating on full query strings
            return quote(probe, safe="&")
        return probe

    def build_query_string(self, probe, parameter_name, additional_params=None):
        """Constructs a URL with query parameters from the given probe and additional parameters.

        Merges into any existing querystring on ``self.event.url``: the probe replaces
        ``parameter_name`` if it's already present, and ``additional_params`` fill in
        alongside. Sibling params already in the URL are preserved.
        """
        params = dict(additional_params) if additional_params else {}
        params[parameter_name] = probe
        return self.lightfuzz.helpers.add_get_params(self.event.url, params, encode=False).geturl()

    def prepare_request(
        self,
        event_type,
        probe,
        cookies,
        additional_params=None,
        speculative_mode="GETPARAM",
        parameter_name_suffix="",
        additional_params_populate_empty=False,
        skip_urlencoding=False,
    ):
        """
        Prepares the request parameters by processing the probe and constructing the request based on the event type.
        """

        if parameter_name_suffix:
            parameter_name = f"{self.parameter_name}{parameter_name_suffix}"
        else:
            parameter_name = self.parameter_name
        additional_params = self.additional_params_process(additional_params, additional_params_populate_empty)

        # Coerce None → "" at the wire boundary (excavate preserves the None/"" distinction
        # in metadata, but browsers serialize both as `name=`; urlencode renders None as "None").
        if additional_params:
            additional_params = {k: ("" if v is None else v) for k, v in additional_params.items()}
        if probe is None:
            probe = ""

        # Transparently pack the probe value into the envelopes, if present
        probe = self.outgoing_probe_value(probe)

        # URL Encode the probe if the event type is GETPARAM or COOKIE, if there are no envelopes, and the submodule did not opt-out with skip_urlencoding
        probe = self.conditional_urlencode(probe, event_type, skip_urlencoding)

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        # Construct request parameters based on the event type
        if event_type == "GETPARAM":
            url = self.build_query_string(probe, parameter_name, additional_params)
            request_params = {"method": "GET", "cookies": cookies, "url": url}
        elif event_type == "COOKIE":
            cookies_probe = {parameter_name: probe}
            request_params = {
                "method": "GET",
                "cookies": {**cookies, **cookies_probe},
                "url": self.event.url,
            }
        elif event_type == "HEADER":
            headers = {parameter_name: probe}
            request_params = {
                "method": "GET",
                "headers": headers,
                "cookies": cookies,
                "url": self.event.url,
            }
        elif event_type in ["POSTPARAM", "BODYJSON"]:
            # Prepare data for POSTPARAM and BODYJSON event types
            data = {parameter_name: probe}
            if additional_params:
                data.update(additional_params)
            if event_type == "BODYJSON":
                request_params = {
                    "method": "POST",
                    "json": data,
                    "cookies": cookies,
                    "url": self.event.url,
                }
            else:
                request_params = {
                    "method": "POST",
                    "data": data,
                    "cookies": cookies,
                    "url": self.event.url,
                }
        else:
            return None

        # Stamp Referer to the form's host page (when distinct from action) — some apps
        # validate Referer for CSRF-like patterns and reject POSTs without it.
        host_url = self.event.data.get("host_url") if isinstance(self.event.data, dict) else None
        if host_url:
            request_params.setdefault("headers", {})
            request_params["headers"]["Referer"] = host_url

        return request_params

    def compare_baseline(
        self,
        event_type,
        probe,
        cookies,
        additional_params_populate_empty=False,
        speculative_mode="GETPARAM",
        skip_urlencoding=False,
        parameter_name_suffix="",
        parameter_name_suffix_additional_params="",
        emit_http_response=True,
    ):
        """Return an HttpCompare for the given request signature, sharing the instance with
        any prior caller with the same signature. Emits one HTTP_RESPONSE per unique baseline
        (set ``emit_http_response=False`` for confirmation/FP-killer baselines)."""
        additional_params = copy.deepcopy(self.event.data.get("additional_params", {}))

        if additional_params and parameter_name_suffix_additional_params:
            # Add suffix to each key in additional_params
            additional_params = {
                f"{k}{parameter_name_suffix_additional_params}": v for k, v in additional_params.items()
            }

        request_params = self.prepare_request(
            event_type,
            probe,
            cookies,
            additional_params,
            speculative_mode,
            parameter_name_suffix,
            additional_params_populate_empty,
            skip_urlencoding,
        )
        request_params.update({"include_cache_buster": False})

        signature = self.lightfuzz._baseline_request_signature(request_params)
        cached = self.lightfuzz.get_cached_baseline(self.event, signature)
        if cached is not None:
            return cached

        if emit_http_response and self.lightfuzz.emit_baseline_responses:
            request_method = request_params.get("method", "GET")
            event = self.event

            async def _on_ready(baseline_response):
                await self.lightfuzz.emit_baseline_response(baseline_response, event, method=request_method)

            request_params["on_baseline_ready"] = _on_ready

        http_compare = self.lightfuzz.helpers.http_compare(**request_params)
        self.lightfuzz.store_cached_baseline(self.event, signature, http_compare)
        return http_compare

    async def baseline_probe(self, cookies, emit_http_response=True):
        """Submit the canonical baseline the way a browser would, returning Probe A's response.

        Probe A: form as captured (``original_value`` + sibling ``additional_params``).
        Probe B: this field populated as ``"a"`` — only fired when ``original_value`` is None/"".
        Catches search-style forms whose content only appears when the primary input is non-empty.
        Both responses are emitted as HTTP_RESPONSE; responses are cached per request signature
        so form siblings share one network request.
        """
        additional_params = copy.deepcopy(self.event.data.get("additional_params", {}))
        probe_value_a = self.incoming_probe_value(populate_empty=False)
        response_a = await self._baseline_probe_once(probe_value_a, cookies, additional_params, emit_http_response)
        if probe_value_a in (None, ""):
            await self._baseline_probe_once("a", cookies, additional_params, emit_http_response)
        return response_a

    async def _baseline_probe_once(self, probe_value, cookies, additional_params, emit_http_response):
        """Fire one baseline request with ``probe_value`` for the fuzzed parameter and
        the captured sibling values, emit the response (subject to caching)."""
        request_params = self.prepare_request(
            self.event.data.get("type", "GETPARAM"),
            probe_value,
            cookies,
            additional_params,
        )
        request_params.update({"allow_redirects": False, "retries": 1, "timeout": 10})

        signature = self.lightfuzz._baseline_request_signature(request_params)
        cache = self.lightfuzz._baseline_probe_response_cache
        cached = cache.get(signature)
        if cached is not None:
            return cached

        response = await self.lightfuzz.helpers.request(**request_params)
        if response is not None:
            if len(cache) >= self.lightfuzz._baseline_probe_response_cache_max:
                cache.pop(next(iter(cache)))
            cache[signature] = response
            if emit_http_response:
                method = request_params.get("method", "GET")
                await self.lightfuzz.emit_baseline_response(response, self.event, method=method)
        return response

    async def compare_probe(
        self,
        http_compare,
        event_type,
        probe,
        cookies,
        additional_params_populate_empty=False,
        additional_params_override={},
        speculative_mode="GETPARAM",
        skip_urlencoding=False,
        parameter_name_suffix="",
        parameter_name_suffix_additional_params="",
    ):
        # Deep copy to avoid modifying original additional_params
        additional_params = copy.deepcopy(self.event.data.get("additional_params", {}))

        # Override additional parameters if provided
        additional_params.update(additional_params_override)

        if additional_params and parameter_name_suffix_additional_params:
            # Add suffix to each key in additional_params
            additional_params = {
                f"{k}{parameter_name_suffix_additional_params}": v for k, v in additional_params.items()
            }

        # Prepare request parameters
        request_params = self.prepare_request(
            event_type,
            probe,
            cookies,
            additional_params,
            speculative_mode,
            parameter_name_suffix,
            additional_params_populate_empty,
            skip_urlencoding,
        )
        # Perform the comparison using the constructed request parameters
        url = request_params.pop("url")
        return await http_compare.compare(url, **request_params)

    async def standard_probe(
        self,
        event_type,
        cookies,
        probe,
        timeout=10,
        additional_params_populate_empty=False,
        speculative_mode="GETPARAM",
        allow_redirects=False,
        skip_urlencoding=False,
    ):
        request_params = self.prepare_request(
            event_type,
            probe,
            cookies,
            self.event.data.get("additional_params"),
            speculative_mode,
            "",
            additional_params_populate_empty,
            skip_urlencoding,
        )
        request_params.update({"allow_redirects": allow_redirects, "retries": 0, "timeout": timeout})
        self.debug(f"standard_probe requested URL: [{request_params['url']}]")
        return await self.lightfuzz.helpers.request(**request_params)

    def conversion_note(self):
        if self.event.data.get("converted_from_post", False):
            return " (converted from POSTPARAM)"
        elif self.event.data.get("converted_from_get", False):
            return " (converted from GETPARAM)"
        return ""

    def metadata(self):
        metadata_string = f"Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}]{self.conversion_note()}"
        original_value = self.event.data.get("original_value")
        if original_value is not None and original_value != "":
            metadata_string += f" Original Value: [{self.lightfuzz.helpers.truncate_string(original_value, 200)}]"
        # Surface additional_params for param types where they're needed to reproduce findings
        if self.event.data["type"] in ("POSTPARAM", "BODYJSON", "HEADER", "COOKIE"):
            additional_params = self.event.data.get("additional_params", {})
            if additional_params:
                # Truncate individual values and the total string to keep descriptions manageable
                truncated = {
                    k: self.lightfuzz.helpers.truncate_string(str(v), 50) for k, v in additional_params.items()
                }
                params_str = self.lightfuzz.helpers.truncate_string(str(truncated), 500)
                metadata_string += f" Additional Params: {params_str}"
        return metadata_string

    def incoming_probe_value(self, populate_empty=True):
        """
        Transparently modifies the incoming probe value (the original value of the WEB_PARAMETER), given any envelopes that may have been identified, so that fuzzing within the envelopes can occur.

        Submodules that set `skip_envelopes = True` receive the raw outer
        value unchanged — used when the submodule's payloads ARE the wire
        format and should not be unwrapped.
        """
        envelopes = getattr(self.event, "envelopes", None)
        probe_value = None
        if envelopes is not None and not self.skip_envelopes:
            probe_value = envelopes.get_subparam()
            self.debug(f"incoming_probe_value (after unpacking): {probe_value} with envelopes [{envelopes}]")
        elif envelopes is not None and self.skip_envelopes:
            # Honor the outer-only opt-out: return the raw original value.
            probe_value = self.event.data.get("original_value")
            self.debug(
                f"incoming_probe_value (skip_envelopes=True): returning raw outer value [{probe_value}] "
                f"instead of unwrapping [{envelopes}]"
            )
        if probe_value is None or probe_value == "":
            if populate_empty is True:
                probe_value = self.lightfuzz.helpers.rand_string(10, numeric_only=True)
            else:
                probe_value = ""
        probe_value = str(probe_value)
        return probe_value

    def outgoing_probe_value(self, outgoing_probe_value):
        """
        Transparently packs the outgoing probe value (fuzz probe being sent to the target) through
        any envelopes that may have been identified, so that fuzzing within the envelopes can occur.

        Submodules that set `skip_envelopes = True` have their probe sent
        unchanged — used when the probe's bytes ARE the wire format and
        should not be re-encoded.

        Uses pack_value() to avoid mutating the envelope's internal state, preventing cross-contamination
        between submodules that share the same event/envelope object.
        """
        self.debug(f"outgoing_probe_value (before packing): {outgoing_probe_value} / {self.event}")
        if self.skip_envelopes:
            self.debug(
                f"outgoing_probe_value (skip_envelopes=True): bypassing envelope packing for [{outgoing_probe_value}]"
            )
            return outgoing_probe_value
        envelopes = getattr(self.event, "envelopes", None)
        if envelopes is not None:
            outgoing_probe_value = envelopes.pack_value(outgoing_probe_value)
            self.debug(
                f"outgoing_probe_value (after packing): {outgoing_probe_value} with envelopes [{envelopes}] / {self.event}"
            )
        return outgoing_probe_value

    def get_submodule_name(self):
        """Extracts the submodule name from the class name."""
        return self.__class__.__name__.replace("Lightfuzz", "").lower()

    def log(self, level, message, *args, **kwargs):
        submodule_name = self.get_submodule_name()
        prefixed_message = f"[{submodule_name}] {message}"
        log_method = getattr(self.lightfuzz, level)
        log_method(prefixed_message, *args, **kwargs)

    def debug(self, message, *args, **kwargs):
        self.log("debug", message, *args, **kwargs)

    def verbose(self, message, *args, **kwargs):
        self.log("verbose", message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self.log("info", message, *args, **kwargs)

    def hugeinfo(self, message, *args, **kwargs):
        self.log("hugeinfo", message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.log("warning", message, *args, **kwargs)

    def hugewarning(self, message, *args, **kwargs):
        self.log("hugewarning", message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.log("error", message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        self.log("critical", message, *args, **kwargs)
