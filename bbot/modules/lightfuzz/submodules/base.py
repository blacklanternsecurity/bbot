import copy
import base64
import binascii
from urllib.parse import quote


class BaseLightfuzz:
    friendly_name = ""
    uses_interactsh = False

    def __init__(self, lightfuzz, event):
        self.lightfuzz = lightfuzz
        self.event = event
        self.results = []
        self.parameter_name = self.event.data["name"]

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
        except (binascii.Error, UnicodeDecodeError):
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
        """Constructs a URL with query parameters from the given probe and additional parameters."""
        url = f"{self.event.data['url']}?{parameter_name}={probe}"
        if additional_params:
            url = self.lightfuzz.helpers.add_get_params(url, additional_params, encode=False).geturl()
        return url

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

        # Transparently pack the probe value into the envelopes, if present
        probe = self.outgoing_probe_value(probe)

        # URL Encode the probe if the event type is GETPARAM or COOKIE, if there are no envelopes, and the submodule did not opt-out with skip_urlencoding
        probe = self.conditional_urlencode(probe, event_type, skip_urlencoding)

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        # Construct request parameters based on the event type
        if event_type == "GETPARAM":
            url = self.build_query_string(probe, parameter_name, additional_params)
            return {"method": "GET", "cookies": cookies, "url": url}
        elif event_type == "COOKIE":
            cookies_probe = {parameter_name: probe}
            return {"method": "GET", "cookies": {**cookies, **cookies_probe}, "url": self.event.data["url"]}
        elif event_type == "HEADER":
            headers = {parameter_name: probe}
            return {"method": "GET", "headers": headers, "cookies": cookies, "url": self.event.data["url"]}
        elif event_type in ["POSTPARAM", "BODYJSON"]:
            # Prepare data for POSTPARAM and BODYJSON event types
            data = {parameter_name: probe}
            if additional_params:
                data.update(additional_params)
            if event_type == "BODYJSON":
                return {"method": "POST", "json": data, "cookies": cookies, "url": self.event.data["url"]}
            else:
                return {"method": "POST", "data": data, "cookies": cookies, "url": self.event.data["url"]}

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
    ):
        """
        Compares the baseline using prepared request parameters.
        """
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
        return self.lightfuzz.helpers.http_compare(**request_params)

    async def baseline_probe(self, cookies):
        """
        Executes a baseline probe to establish a baseline for comparison.
        """
        if self.event.data.get("eventtype") in ["POSTPARAM", "BODYJSON"]:
            method = "POST"
        else:
            method = "GET"

        return await self.lightfuzz.helpers.request(
            method=method,
            cookies=cookies,
            url=self.event.data.get("url"),
            allow_redirects=False,
            retries=1,
            timeout=10,
        )

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

    def metadata(self):
        metadata_string = f"Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}]"
        if self.event.data["original_value"] != "" and self.event.data["original_value"] is not None:
            metadata_string += (
                f" Original Value: [{self.lightfuzz.helpers.truncate_string(self.event.data['original_value'], 200)}]"
            )
        return metadata_string

    def incoming_probe_value(self, populate_empty=True):
        """
        Transparently modifies the incoming probe value (the original value of the WEB_PARAMETER), given any envelopes that may have been identified, so that fuzzing within the envelopes can occur.
        """
        envelopes = getattr(self.event, "envelopes", None)
        probe_value = ""
        if envelopes is not None:
            probe_value = envelopes.get_subparam()
            self.debug(f"incoming_probe_value (after unpacking): {probe_value} with envelopes [{envelopes}]")
        if not probe_value:
            if populate_empty is True:
                probe_value = self.lightfuzz.helpers.rand_string(10, numeric_only=True)
            else:
                probe_value = ""
        probe_value = str(probe_value)
        return probe_value

    def outgoing_probe_value(self, outgoing_probe_value):
        """
        Transparently modifies the outgoing probe value (fuzz probe being sent to the target), given any envelopes that may have been identified, so that fuzzing within the envelopes can occur.
        """
        self.debug(f"outgoing_probe_value (before packing): {outgoing_probe_value} / {self.event}")
        envelopes = getattr(self.event, "envelopes", None)
        if envelopes is not None:
            envelopes.set_subparam(value=outgoing_probe_value)
            outgoing_probe_value = envelopes.pack()
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
