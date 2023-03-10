import re
from threading import Lock

from bbot.modules.base import BaseModule

valid_chars = "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}]]"


def encode_all(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)


class iis_shortnames(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_HINT"]
    flags = ["active", "safe", "web-basic", "web-thorough", "iis-shortnames"]
    meta = {"description": "Check for IIS shortname vulnerability"}
    options = {"detect_only": True, "max_node_count": 30}
    options_desc = {
        "detect_only": "Only detect the vulnerability and do not run the shortname scanner",
        "max_node_count": "Limit how many nodes to attempt to resolve on any given recursion branch",
    }
    in_scope_only = True

    max_event_handlers = 8

    def detect(self, target):
        technique = None
        detections = []
        random_string = self.helpers.rand_string(8)
        control_url = f"{target}{random_string}*~1*/a.aspx"
        test_url = f"{target}*~1*/a.aspx"

        for method in ["GET", "POST", "OPTIONS", "DEBUG", "HEAD", "TRACE"]:
            control = self.helpers.request(method=method, url=control_url, allow_redirects=False, retries=2)
            test = self.helpers.request(method=method, url=test_url, allow_redirects=False, retries=2)
            if (control != None) and (test != None):
                if control.status_code != test.status_code:
                    technique = f"{str(control.status_code)}/{str(test.status_code)} HTTP Code"
                    detections.append((method, test.status_code, technique))

                elif ("Error Code</th><td>0x80070002" in control.text) and (
                    "Error Code</th><td>0x00000000" in test.text
                ):
                    detections.append((method, 0, technique))
                    technique = "HTTP Body Error Message"
        return detections

    def setup(self):
        self.scanned_tracker_lock = Lock()
        self.scanned_tracker = set()
        return True

    @staticmethod
    def normalize_url(url):
        return str(url.rstrip("/") + "/").lower()

    def directory_confirm(self, target, method, url_hint, affirmative_status_code):
        payload = encode_all(f"{url_hint}")
        url = f"{target}{payload}"
        directory_confirm_result = self.helpers.request(method=method, url=url, allow_redirects=False, retries=2)

        if directory_confirm_result.status_code == affirmative_status_code:
            return True
        else:
            return False

    def duplicate_check(self, target, method, url_hint, affirmative_status_code):
        duplicates = []
        count = 2
        base_hint = re.sub(r"~\d", "", url_hint)
        suffix = "\\a.aspx"

        while 1:
            payload = encode_all(f"{base_hint}~{str(count)}*")
            url = f"{target}{payload}{suffix}"

            duplicate_check_results = self.helpers.request(method=method, url=url, allow_redirects=False, retries=2)
            if duplicate_check_results.status_code != affirmative_status_code:
                break
            else:
                duplicates.append(f"{base_hint}~{str(count)}")
                count += 1

            if count > 5:
                self.warning("Found more than 5 files with the same shortname. Will stop further duplicate checking.")
                break

        return duplicates

    def threaded_request(self, method, url, affirmative_status_code):
        r = self.helpers.request(method=method, url=url, allow_redirects=False, retries=2)
        if r is not None:
            if r.status_code == affirmative_status_code:
                return True

    def solve_shortname_recursive(
        self, method, target, prefix, affirmative_status_code, extension_mode=False, node_count=0
    ):
        url_hint_list = []
        found_results = False

        futures = {}
        for c in valid_chars:
            suffix = "\\a.aspx"
            wildcard = "*" if extension_mode else "*~1*"
            payload = encode_all(f"{prefix}{c}{wildcard}")
            url = f"{target}{payload}{suffix}"
            future = self.submit_task(self.threaded_request, method, url, affirmative_status_code)
            futures[future] = c

        for future in self.helpers.as_completed(futures):
            c = futures[future]
            result = future.result()
            if result:
                found_results = True
                node_count += 1
                self.verbose(f"node_count: {str(node_count)} for node: {target}")
                if node_count > self.config.get("max_node_count"):
                    self.warning(
                        f"iis_shortnames: max_node_count ({str(self.config.get('max_node_count'))}) exceeded for node: {target}. Affected branch will be terminated."
                    )
                    return url_hint_list

                # check to make sure the file isn't shorter than 6 characters
                wildcard = "~1*"
                payload = encode_all(f"{prefix}{c}{wildcard}")
                url = f"{target}{payload}{suffix}"
                r = self.helpers.request(method=method, url=url, allow_redirects=False, retries=2)
                if r is not None:
                    if r.status_code == affirmative_status_code:
                        url_hint_list.append(f"{prefix}{c}")

                url_hint_list += self.solve_shortname_recursive(
                    method, target, f"{prefix}{c}", affirmative_status_code, extension_mode, node_count=node_count
                )
        if len(prefix) > 0 and found_results == False:
            url_hint_list.append(f"{prefix}")
            self.verbose(f"Found new (possibly partial) URL_HINT: {prefix} from node {target}")
        return url_hint_list

    def handle_event(self, event):
        normalized_url = self.normalize_url(event.data)
        with self.scanned_tracker_lock:
            self.scanned_tracker.add(normalized_url)

        detections = self.detect(normalized_url)

        technique_strings = []
        if detections:
            for detection in detections:
                method, affirmative_status_code, technique = detection
                technique_strings.append(f"{method} ({technique})")

            description = f"IIS Shortname Vulnerability Detected. Potentially Vulnerable Method/Techniques: [{','.join(technique_strings)}]"
            self.emit_event(
                {"severity": "LOW", "host": str(event.host), "url": normalized_url, "description": description},
                "VULNERABILITY",
                event,
            )
            if not self.config.get("detect_only"):
                for detection in detections:
                    method, affirmative_status_code, technique = detection
                    valid_method_confirmed = False

                    if valid_method_confirmed:
                        break

                    file_name_hints = list(
                        set(self.solve_shortname_recursive(method, normalized_url, "", affirmative_status_code))
                    )
                    if len(file_name_hints) == 0:
                        continue
                    else:
                        valid_method_confirmed = True

                    file_name_hints = [f"{x}~1" for x in file_name_hints]
                    url_hint_list = []

                    file_name_hints_dedupe = file_name_hints[:]

                    for x in file_name_hints_dedupe:
                        duplicates = self.duplicate_check(normalized_url, method, x, affirmative_status_code)
                        if duplicates:
                            file_name_hints += duplicates

                    # check for the case of a folder and file with the same filename

                    for d in file_name_hints:
                        if self.directory_confirm(normalized_url, method, d, affirmative_status_code):
                            self.verbose(f"Confirmed Directory URL_HINT: {d} from node {normalized_url}")
                            url_hint_list.append(d)

                    for y in file_name_hints:
                        file_name_extension_hints = self.solve_shortname_recursive(
                            method, normalized_url, f"{y}.", affirmative_status_code, extension_mode=True
                        )
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
                        self.emit_event(f"{normalized_url}/{url_hint}", "URL_HINT", event, tags=[hint_type])

    def filter_event(self, event):
        if "dir" in event.tags:
            with self.scanned_tracker_lock:
                if self.normalize_url(event.data) not in self.scanned_tracker:
                    return True
                return False
        return False
