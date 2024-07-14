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
            if v == "":
                new_additional_params[k] = self.lightfuzz.helpers.rand_string(8, numeric_only=True)
            else:
                new_additional_params[k] = v
        return new_additional_params

    async def send_probe(self, probe):
        getparams = {self.event.data["name"]: probe}
        url = self.lightfuzz.helpers.add_get_params(self.event.data["url"], getparams).geturl()
        self.lightfuzz.debug(f"lightfuzz sending probe with URL: {url}")
        r = await self.lightfuzz.helpers.request(method="GET", url=url, allow_redirects=False, retries=2, timeout=10)
        if r:
            return r.text

    def compare_baseline(
        self, event_type, probe, cookies, additional_params_populate_empty=False, speculative_mode="GETPARAM"
    ):

        http_compare = None

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        if event_type == "GETPARAM":
            baseline_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
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
        return http_compare

    async def compare_probe(
        self,
        http_compare,
        event_type,
        probe,
        cookies,
        additional_params_populate_empty=False,
        speculative_mode="GETPARAM",
    ):

        http_compare = None

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        if event_type == "GETPARAM":
            probe_url = f"{self.event.data['url']}?{self.event.data['name']}={probe}"
            compare_result = await http_compare.compare(probe_url, cookies=cookies)
        elif event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe}
            compare_result = await http_compare.compare(self.event.data["url"], cookies={**cookies, **cookies_probe})
        elif event_type == "HEADER":
            headers = {self.event.data["name"]: f"{probe}"}
            compare_result = await http_compare.compare(self.event.data["url"], headers=headers, cookies=cookies)
        elif event_type == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe}"}
            if self.event.data["additional_params"] is not None:
                data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )
            compare_result = await http_compare.compare(
                self.event.data["url"], method="POST", data=data, cookies=cookies
            )
        return compare_result

    async def standard_probe(
        self,
        event_type,
        cookies,
        probe_value,
        timeout=10,
        additional_params_populate_empty=False,
        speculative_mode="GETPARAM",
    ):

        if event_type == "SPECULATIVE":
            event_type = speculative_mode

        method = "GET"
        if event_type == "GETPARAM":
            url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}"
        else:
            url = self.event.data["url"]
        if event_type == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe_value}
            cookies = {**cookies, **cookies_probe}
        if event_type == "HEADER":
            headers = {self.event.data["name"]: probe_value}
        else:
            headers = {}
        if event_type == "POSTPARAM":
            method = "POST"
            data = {self.event.data["name"]: probe_value}
            if self.event.data["additional_params"] is not None:
                data.update(
                    self.additional_params_process(
                        self.event.data["additional_params"], additional_params_populate_empty
                    )
                )
        else:
            data = {}
        self.lightfuzz.debug(f"standard_probe requested URL: [{url}]")
        return await self.lightfuzz.helpers.request(
            method=method,
            cookies=cookies,
            headers=headers,
            data=data,
            url=url,
            allow_redirects=False,
            retries=0,
            timeout=timeout,
        )
