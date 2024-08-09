import re

from bbot.modules.base import BaseModule

valid_chars = "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}]]"


def encode_all(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)


class IISShortnamesError(Exception):
    pass


class iis_shortnames(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_HINT"]
    flags = ["active", "safe", "web-basic", "iis-shortnames"]
    meta = {
        "description": "Check for IIS shortname vulnerability",
        "created_date": "2022-04-15",
        "author": "@pmueller",
    }
    options = {"detect_only": True, "max_node_count": 50}
    options_desc = {
        "detect_only": "Only detect the vulnerability and do not run the shortname scanner",
        "max_node_count": "Limit how many nodes to attempt to resolve on any given recursion branch",
    }
    in_scope_only = True

    _module_threads = 8

    async def detect(self, target):
        technique = None
        detections = []
        random_string = self.helpers.rand_string(8)
        control_url = f"{target}{random_string}*~1*/a.aspx"
        test_url = f"{target}*~1*/a.aspx"

        urls_and_kwargs = []
        for method in ["GET", "POST", "OPTIONS", "DEBUG", "HEAD", "TRACE"]:
            kwargs = dict(method=method, allow_redirects=False, timeout=10)
            urls_and_kwargs.append((control_url, kwargs, method))
            urls_and_kwargs.append((test_url, kwargs, method))

        results = {}
        async for url, kwargs, method, response in self.helpers.request_custom_batch(urls_and_kwargs):
            try:
                results[method][url] = response
            except KeyError:
                results[method] = {url: response}
        for method, result in results.items():
            confirmations = 0
            iterations = 4  # one failed detection is tolerated, as long as its not the first run
            while iterations > 0:
                control = results[method].get(control_url, None)
                test = results[method].get(test_url, None)
                if control and test:
                    if control.status_code != test.status_code:
                        confirmations += 1
                        self.debug(f"New detection, number of confirmations: [{str(confirmations)}]")
                        if confirmations > 2:
                            technique = f"{str(control.status_code)}/{str(test.status_code)} HTTP Code"
                            detections.append((method, test.status_code, technique))
                            break
                    elif ("Error Code</th><td>0x80070002" in control.text) and (
                        "Error Code</th><td>0x00000000" in test.text
                    ):
                        confirmations += 1
                        if confirmations > 2:
                            detections.append((method, 0, technique))
                            technique = "HTTP Body Error Message"
                            break
                iterations -= 1
                if confirmations == 0:
                    break
        return detections

    async def setup(self):
        self.scanned_tracker = set()
        return True

    @staticmethod
    def normalize_url(url):
        return str(url.rstrip("/") + "/").lower()

    async def directory_confirm(self, target, method, url_hint, affirmative_status_code):
        payload = encode_all(f"{url_hint}")
        url = f"{target}{payload}"
        directory_confirm_result = await self.helpers.request(
            method=method, url=url, allow_redirects=False, retries=2, timeout=10
        )
        if directory_confirm_result is not None:
            if directory_confirm_result.status_code == affirmative_status_code:
                return True
        return False

    async def duplicate_check(self, target, method, url_hint, affirmative_status_code):
        duplicates = []
        count = 2
        base_hint = re.sub(r"~\d", "", url_hint)
        suffix = "/a.aspx"

        while 1:
            payload = encode_all(f"{base_hint}~{str(count)}*")
            url = f"{target}{payload}{suffix}"

            duplicate_check_results = await self.helpers.request(
                method=method, url=url, allow_redirects=False, retries=2, timeout=10
            )

            if not duplicate_check_results:
                self.debug("duplicate check produced NoneType sample")
                break

            if duplicate_check_results.status_code != affirmative_status_code:
                break
            else:
                duplicates.append(f"{base_hint}~{str(count)}")
                count += 1

            if count > 5:
                self.warning("Found more than 5 files with the same shortname. Will stop further duplicate checking.")
                break

        return duplicates

    async def threaded_request(self, method, url, affirmative_status_code, c):
        r = await self.helpers.request(method=method, url=url, allow_redirects=False, retries=2, timeout=10)
        if r is not None:
            if r.status_code == affirmative_status_code:
                return True, c
        return None, c

    async def solve_valid_chars(self, method, target, affirmative_status_code):
        confirmed_chars = []
        confirmed_exts = []
        suffix = "/a.aspx"

        urls_and_kwargs = []
        kwargs = dict(method=method, allow_redirects=False, retries=2, timeout=10)
        for c in valid_chars:
            for file_part in ("stem", "ext"):
                payload = encode_all(f"*{c}*~1*")
                url = f"{target}{payload}{suffix}"
                urls_and_kwargs.append((url, kwargs, (c, file_part)))

        async for url, kwargs, (c, file_part), response in self.helpers.request_custom_batch(urls_and_kwargs):
            if response is not None:
                if response.status_code == affirmative_status_code:
                    if file_part == "stem":
                        confirmed_chars.append(c)
                    elif file_part == "ext":
                        confirmed_exts.append(c)

        return confirmed_chars, confirmed_exts

    async def solve_shortname_recursive(
        self,
        safety_counter,
        method,
        target,
        prefix,
        affirmative_status_code,
        char_list,
        ext_char_list,
        extension_mode=False,
        node_count=0,
    ):
        url_hint_list = []
        found_results = False

        cl = ext_char_list if extension_mode == True else char_list

        urls_and_kwargs = []

        for c in cl:
            suffix = "/a.aspx"
            wildcard = "*" if extension_mode else "*~1*"
            payload = encode_all(f"{prefix}{c}{wildcard}")
            url = f"{target}{payload}{suffix}"
            kwargs = dict(method=method)
            urls_and_kwargs.append((url, kwargs, c))

        async for url, kwargs, c, response in self.helpers.request_custom_batch(urls_and_kwargs):
            if response is not None:
                if response.status_code == affirmative_status_code:
                    found_results = True
                    node_count += 1
                    safety_counter.counter += 1
                    if safety_counter.counter > 1500:
                        raise IISShortnamesError(f"Exceeded safety counter threshold ({safety_counter.counter})")
                    self.verbose(f"node_count: {str(node_count)} for node: {target}")
                    if node_count > self.config.get("max_node_count"):
                        self.verbose(
                            f"iis_shortnames: max_node_count ({str(self.config.get('max_node_count'))}) exceeded for node: {target}. Affected branch will be terminated."
                        )
                        return url_hint_list

                    # check to make sure the file isn't shorter than 6 characters
                    wildcard = "~1*"
                    payload = encode_all(f"{prefix}{c}{wildcard}")
                    url = f"{target}{payload}{suffix}"
                    r = await self.helpers.request(
                        method=method, url=url, allow_redirects=False, retries=2, timeout=10
                    )
                    if r is not None:
                        if r.status_code == affirmative_status_code:
                            url_hint_list.append(f"{prefix}{c}")

                    url_hint_list += await self.solve_shortname_recursive(
                        safety_counter,
                        method,
                        target,
                        f"{prefix}{c}",
                        affirmative_status_code,
                        char_list,
                        ext_char_list,
                        extension_mode,
                        node_count=node_count,
                    )
        if len(prefix) > 0 and found_results == False:
            url_hint_list.append(f"{prefix}")
            self.verbose(f"Found new (possibly partial) URL_HINT: {prefix} from node {target}")
        return url_hint_list

    async def handle_event(self, event):
        class safety_counter_obj:
            counter = 0

        normalized_url = self.normalize_url(event.data)
        self.scanned_tracker.add(normalized_url)

        detections = await self.detect(normalized_url)

        technique_strings = []
        if detections:
            for detection in detections:
                method, affirmative_status_code, technique = detection
                technique_strings.append(f"{method} ({technique})")

            description = f"IIS Shortname Vulnerability Detected. Potentially Vulnerable Method/Techniques: [{','.join(technique_strings)}]"
            await self.emit_event(
                {"severity": "LOW", "host": str(event.host), "url": normalized_url, "description": description},
                "VULNERABILITY",
                event,
                context=f"{{module}} detected low {{event.type}}: IIS shortname enumeration",
            )
            if not self.config.get("detect_only"):
                for detection in detections:
                    safety_counter = safety_counter_obj()

                    method, affirmative_status_code, technique = detection
                    valid_method_confirmed = False

                    if valid_method_confirmed:
                        break

                    confirmed_chars, confirmed_exts = await self.solve_valid_chars(
                        method, normalized_url, affirmative_status_code
                    )

                    if len(confirmed_chars) >= len(valid_chars) - 4:
                        self.debug(
                            f"Detected [{len(confirmed_chars)}] characters (out of {len(valid_chars)}) as valid. This is likely a false positive"
                        )
                        continue

                    if len(confirmed_chars) > 0:
                        valid_method_confirmed = True
                    else:
                        continue

                    self.debug(f"Confirmed character list: {','.join(confirmed_chars)}")
                    self.debug(f"Confirmed character list: {','.join(confirmed_exts)}")
                    try:
                        file_name_hints = list(
                            set(
                                await self.solve_shortname_recursive(
                                    safety_counter,
                                    method,
                                    normalized_url,
                                    "",
                                    affirmative_status_code,
                                    confirmed_chars,
                                    confirmed_exts,
                                )
                            )
                        )
                    except IISShortnamesError as e:
                        self.warning(f"Aborted Shortname Run for URL [{normalized_url}] due to Error: [{e}]")
                        return

                    file_name_hints = [f"{x}~1" for x in file_name_hints]
                    url_hint_list = []

                    file_name_hints_dedupe = file_name_hints[:]

                    for x in file_name_hints_dedupe:
                        duplicates = await self.duplicate_check(normalized_url, method, x, affirmative_status_code)
                        if duplicates:
                            file_name_hints += duplicates

                    # check for the case of a folder and file with the same filename
                    for d in file_name_hints:
                        if await self.directory_confirm(normalized_url, method, d, affirmative_status_code):
                            self.verbose(f"Confirmed Directory URL_HINT: {d} from node {normalized_url}")
                            url_hint_list.append(d)

                    for y in file_name_hints:
                        try:
                            file_name_extension_hints = await self.solve_shortname_recursive(
                                safety_counter,
                                method,
                                normalized_url,
                                f"{y}.",
                                affirmative_status_code,
                                confirmed_chars,
                                confirmed_exts,
                                extension_mode=True,
                            )
                        except IISShortnamesError as e:
                            self.warning(f"Aborted Shortname Run for URL {normalized_url} due to Error: [{e}]")
                            return

                        for z in file_name_extension_hints:
                            if z.endswith("."):
                                z = z.rstrip(".")
                            self.verbose(f"Found new file URL_HINT: {z} from node {normalized_url}")
                            url_hint_list.append(z)

                    for url_hint in url_hint_list:
                        if "." in url_hint:
                            hint_type = "shortname-file"
                        else:
                            hint_type = "shortname-directory"
                        await self.emit_event(
                            f"{normalized_url}/{url_hint}",
                            "URL_HINT",
                            event,
                            tags=[hint_type],
                            context=f"{{module}} enumerated shortnames at {normalized_url} and found {{event.type}}: {url_hint}",
                        )

    async def filter_event(self, event):
        if "dir" in event.tags:
            if self.normalize_url(event.data) not in self.scanned_tracker:
                return True
            return False
        return False
