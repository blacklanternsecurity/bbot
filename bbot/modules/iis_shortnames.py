from bbot.modules.base import BaseModule

valid_chars = "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}]]"


def encode_all(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)


class iis_shortnames(BaseModule):

    watched_events = ["URL"]
    produced_events = ["URL_HINT"]
    flags = ["active", "safe", "web-basic", "iis-shortnames"]
    meta = {"description": "Check for IIS shortname vulnerability"}
    options = {"detect_only": True, "threads": 8}
    options_desc = {
        "detect_only": "Only detect the vulnerability and do not run the shortname scanner",
        "threads": "the number of threads to run concurrently when executing the IIS shortname scanner",
    }
    in_scope_only = True

    def detect(self, target):
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
        return detected

    def duplicate_check(self, target, method, url_hint):

        duplicates = []
        headers = {}
        count = 2
        while 1:
            payload = encode_all(url_hint.replace("~1", f"*~{str(count)}*\\a.aspx"))
            url = f"{target}{payload}"

            duplicate_check_results = self.helpers.request(method=method, headers=headers, url=url)
            if duplicate_check_results.status_code != 404:
                break
            duplicates.append(url_hint.replace("~1", f"~{str(count)}"))
            count += 1

            if count > 5:
                self.warning("Found more than 5 files with the same shortname. Will stop further duplicate checking.")
                break

        return duplicates

    def threaded_request(self, method, url):
        r = self.helpers.request(method=method, url=url)
        if r.status_code == 404:
            return True
        else:
            return False

    def solve_shortname_recursive(self, method, target, prefix, extension_mode=False):
        url_hint_list = []
        found_results = False

        futures = {}
        for c in valid_chars:
            suffix = "\\"
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
                url_hint_list += self.solve_shortname_recursive(method, target, f"{prefix}{c}", extension_mode)
        if len(prefix) > 0 and found_results == False:
            url_hint_list.append(f"{prefix}")
        return url_hint_list

    def handle_event(self, event):
        normalized_url = event.data.rstrip("/") + "/"
        vulnerable_methods = self.detect(normalized_url)
        if vulnerable_methods:
            description = f"IIS Shortname Vulnerability Detected. Vulnerable methods: [{','.join(vulnerable_methods)}]"
            self.emit_event(
                {"severity": "LOW", "host": str(event.host), "url": normalized_url, "description": description},
                "VULNERABILITY",
                event,
            )
            if not self.config.get("detect_only"):

                file_name_hints = self.solve_shortname_recursive(vulnerable_methods[0], normalized_url, "")
                file_name_hints = [f"{x}~1" for x in file_name_hints]

                url_hint_list = []
                for x in file_name_hints:
                    duplicates = self.duplicate_check(normalized_url, vulnerable_methods[0], x)
                    if duplicates:
                        file_name_hints += duplicates

                for y in file_name_hints:
                    file_name_extension_hints = self.solve_shortname_recursive(
                        vulnerable_methods[0], normalized_url, f"{y}.", extension_mode=True
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
