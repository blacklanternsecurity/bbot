import re

from bbot.modules.base import BaseModule

valid_chars = "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}]]"


def encode_all(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)


class iis_shortnames(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_HINT"]
    flags = ["active", "safe", "web-basic", "iis-shortnames"]
    meta = {"description": "Check for IIS shortname vulnerability"}
    options = {"detect_only": True}
    options_desc = {"detect_only": "Only detect the vulnerability and do not run the shortname scanner"}
    in_scope_only = True

    max_event_handlers = 8

    def detect(self, target):
        technique = None
        headers = {}
        detected = []
        random_string = self.helpers.rand_string(8)
        control_url = f"{target}{random_string}*~1*/a.aspx"
        test_url = f"{target}*~1*/a.aspx"

        for method in ["GET", "POST", "OPTIONS", "DEBUG", "HEAD", "TRACE"]:
            control = self.helpers.request(method=method, headers=headers, url=control_url)
            test = self.helpers.request(method=method, headers=headers, url=test_url)
            if (control != None) and (test != None):
                if (control.status_code != 404) and (test.status_code == 404):
                    detected.append(method)
                    technique = "400/404 HTTP Code"

                elif ("Error Code</th><td>0x80070002" in control.text) and (
                    "Error Code</th><td>0x00000000" in test.text
                ):
                    detected.append(method)
                    technique = "HTTP Body Error Message"
        return detected, technique

    def duplicate_check(self, target, method, url_hint):
        duplicates = []
        headers = {}
        count = 2
        base_hint = re.sub(r"~\d", "", url_hint)
        suffix = "\\a.aspx"

        while 1:
            payload = encode_all(f"{base_hint}~{str(count)}*")
            url = f"{target}{payload}{suffix}"

            duplicate_check_results = self.helpers.request(method=method, headers=headers, url=url)
            if duplicate_check_results.status_code != 404:
                break
            else:
                duplicates.append(f"{base_hint}~{str(count)}")
                count += 1

            if count > 5:
                self.warning("Found more than 5 files with the same shortname. Will stop further duplicate checking.")
                break

        return duplicates

    def threaded_request(self, method, url):
        r = self.helpers.request(method=method, url=url)
        if r is not None:
            if r.status_code == 404:
                return True

    def solve_shortname_recursive(self, method, target, prefix, extension_mode=False):
        url_hint_list = []
        found_results = False

        futures = {}
        for c in valid_chars:
            suffix = "\\a.aspx"
            wildcard = "*" if extension_mode else "*~1*"
            payload = encode_all(f"{prefix}{c}{wildcard}")
            url = f"{target}{payload}{suffix}"
            future = self.submit_task(self.threaded_request, method, url)
            futures[future] = c

        for future in self.helpers.as_completed(futures):
            c = futures[future]
            result = future.result()
            if result:
                found_results = True

                # check to make sure the file isn't shorter than 6 characters
                wildcard = "~1*"
                payload = encode_all(f"{prefix}{c}{wildcard}")
                url = f"{target}{payload}{suffix}"
                r = self.helpers.request(method=method, url=url)
                if r is not None:
                    if r.status_code == 404:
                        url_hint_list.append(f"{prefix}{c}")

                url_hint_list += self.solve_shortname_recursive(method, target, f"{prefix}{c}", extension_mode)
        if len(prefix) > 0 and found_results == False:
            url_hint_list.append(f"{prefix}")
        return url_hint_list

    def handle_event(self, event):
        normalized_url = event.data.rstrip("/") + "/"
        vulnerable_methods, technique = self.detect(normalized_url)
        if vulnerable_methods:
            description = f"IIS Shortname Vulnerability Detected. Potentially Vulnerable methods: [{','.join(vulnerable_methods)}] Technique: [{technique}]"
            self.emit_event(
                {"severity": "LOW", "host": str(event.host), "url": normalized_url, "description": description},
                "VULNERABILITY",
                event,
            )
            if not self.config.get("detect_only"):
                valid_method_confirmed = False
                for m in vulnerable_methods:
                    if valid_method_confirmed:
                        break

                    file_name_hints = self.solve_shortname_recursive(m, normalized_url, "")
                    if len(file_name_hints) == 0:
                        continue
                    else:
                        valid_method_confirmed = True

                    file_name_hints = [f"{x}~1" for x in file_name_hints]
                    url_hint_list = []

                    file_name_hints_dedupe = file_name_hints[:]

                    for x in file_name_hints_dedupe:
                        duplicates = self.duplicate_check(normalized_url, m, x)
                        if duplicates:
                            file_name_hints += duplicates

                    for y in file_name_hints:
                        file_name_extension_hints = self.solve_shortname_recursive(
                            m, normalized_url, f"{y}.", extension_mode=True
                        )
                        for z in file_name_extension_hints:
                            url_hint_list.append(z)

                    for url_hint in url_hint_list:
                        if url_hint.endswith("."):
                            url_hint = url_hint.rstrip(".")
                        if "." in url_hint:
                            hint_type = "shortname-file"
                        else:
                            hint_type = "shortname-directory"
                        self.emit_event(f"{normalized_url}/{url_hint}", "URL_HINT", event, tags=[hint_type])
