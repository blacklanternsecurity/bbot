import copy


class BaseLightfuzz:
    def __init__(self, lightfuzz, event):
        self.lightfuzz = lightfuzz
        self.event = event
        self.results = []

    def additional_params_process(self, additional_params, additional_params_populate_blank_empty):
        if additional_params_populate_blank_empty == False:
            return additional_params
        new_additional_params = {}
        for k, v in additional_params.items():
            if v == "" or v == None:
                new_additional_params[k] = self.lightfuzz.helpers.rand_string(10, numeric_only=True)
            else:
                new_additional_params[k] = v
        return new_additional_params

    async def send_probe(self, probe):
        probe = self.probe_value_outgoing(probe)
        getparams = {self.event.data["name"]: probe}
        url = self.lightfuzz.helpers.add_get_params(self.event.data["url"], getparams, encode=False).geturl()
        self.lightfuzz.debug(f"lightfuzz sending probe with URL: {url}")
        r = await self.lightfuzz.helpers.request(method="GET", url=url, allow_redirects=False, retries=2, timeout=10)
        if r:
            return r.text

    def compare_baseline(
        self, event_type, probe, cookies, additional_params_populate_empty=False, speculative_mode="GETPARAM"
    ):
        probe = self.probe_value_outgoing(probe)
        http_compare = None

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        if event_type == "GETPARAM":
            baseline_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            if "additional_params" in self.event.data.keys() and self.event.data["additional_params"] is not None:
                baseline_url = self.lightfuzz.helpers.add_get_params(
                    baseline_url, self.event.data["additional_params"], encode=False
                ).geturl()
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, cookies=cookies, include_cache_buster=False
            )
        elif event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: f"{probe}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], include_cache_buster=False, cookies={**cookies, **cookies_probe}
            )
        elif event_type == "HEADER":
            headers = {self.event.data["name"]: f"{probe}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], include_cache_buster=False, headers=headers, cookies=cookies
            )
        elif event_type == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe}"}
            if self.event.data["additional_params"] is not None:
                data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], method="POST", include_cache_buster=False, data=data, cookies=cookies
            )
        elif event_type == "BODYJSON":
            data = {self.event.data["name"]: f"{probe}"}
            if self.event.data["additional_params"] is not None:
                data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )
            http_compare = self.lightfuzz.helpers.http_compare(
                self.event.data["url"], method="POST", include_cache_buster=False, json=data, cookies=cookies
            )
        return http_compare

    async def baseline_probe(self, cookies):
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
    ):

        probe = self.probe_value_outgoing(probe)
        additional_params = copy.deepcopy(self.event.data.get("additional_params", {}))
        if additional_params_override:
            for k, v in additional_params_override.items():
                additional_params[k] = v

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        if event_type == "GETPARAM":
            probe_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            if additional_params:
                probe_url = self.lightfuzz.helpers.add_get_params(probe_url, additional_params, encode=False).geturl()
            compare_result = await http_compare.compare(probe_url, cookies=cookies)
        elif event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe}
            compare_result = await http_compare.compare(self.event.data["url"], cookies={**cookies, **cookies_probe})
        elif event_type == "HEADER":
            headers = {self.event.data["name"]: f"{probe}"}
            compare_result = await http_compare.compare(self.event.data["url"], headers=headers, cookies=cookies)
        elif event_type == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe}"}
            if additional_params:
                data.update(self.additional_params_process(additional_params, additional_params_populate_empty))
            compare_result = await http_compare.compare(
                self.event.data["url"], method="POST", data=data, cookies=cookies
            )
        elif event_type == "BODYJSON":
            data = {self.event.data["name"]: f"{probe}"}
            if additional_params:
                data.update(self.additional_params_process(additional_params, additional_params_populate_empty))
            compare_result = await http_compare.compare(
                self.event.data["url"], method="POST", json=data, cookies=cookies
            )
        return compare_result

    async def standard_probe(
        self,
        event_type,
        cookies,
        probe,
        timeout=10,
        additional_params_populate_empty=False,
        speculative_mode="GETPARAM",
    ):

        probe = self.probe_value_outgoing(probe)

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        method = "GET"
        if event_type == "GETPARAM":
            url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            if "additional_params" in self.event.data.keys() and self.event.data["additional_params"] is not None:
                url = self.lightfuzz.helpers.add_get_params(
                    url, self.event.data["additional_params"], encode=False
                ).geturl()
        else:
            url = self.event.data["url"]
        if event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe}
            cookies = {**cookies, **cookies_probe}
        if event_type == "HEADER":
            headers = {self.event.data["name"]: probe}
        else:
            headers = {}

        data = None
        json_data = None

        if event_type == "POSTPARAM":
            method = "POST"
            data = {self.event.data["name"]: probe}
            if self.event.data["additional_params"] is not None:
                data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )
        elif event_type == "BODYJSON":
            method = "POST"
            json_data = {self.event.data["name"]: probe}
            if self.event.data["additional_params"] is not None:
                json_data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )

        self.lightfuzz.debug(f"standard_probe requested URL: [{url}]")
        return await self.lightfuzz.helpers.request(
            method=method,
            cookies=cookies,
            headers=headers,
            data=data,
            json=json_data,
            url=url,
            allow_redirects=False,
            retries=0,
            timeout=timeout,
        )

    def metadata(self):

        metadata_string = f"Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}]"
        if self.event.data["original_value"] != "" and self.event.data["original_value"] != None:
            metadata_string += (
                f" Original Value: [{self.lightfuzz.helpers.truncate_string(self.event.data['original_value'],200)}]"
            )
        return metadata_string

    def probe_value_incoming(self, populate_empty=True):
        probe_value = self.event.data.get("original_value", "")
        if (probe_value is None or len(str(probe_value)) == 0) and populate_empty == True:
            probe_value = self.lightfuzz.helpers.rand_string(10, numeric_only=True)
        self.lightfuzz.debug(f"probe_value_incoming (before modification): {probe_value}")
        envelopes_instance = getattr(self.event, "envelopes", None)
        probe_value = envelopes_instance.remove_envelopes(probe_value)
        self.lightfuzz.debug(f"probe_value_incoming (after modification): {probe_value}")
        if not isinstance(probe_value, str):
            probe_value = str(probe_value)
        return probe_value

    def probe_value_outgoing(self, outgoing_probe_value):
        self.lightfuzz.debug(f"probe_value_outgoing (before modification): {outgoing_probe_value}")
        envelopes_instance = getattr(self.event, "envelopes", None)
        outgoing_probe_value = envelopes_instance.add_envelopes(outgoing_probe_value)
        self.lightfuzz.debug(f"probe_value_outgoing (after modification): {outgoing_probe_value}")
        return outgoing_probe_value
