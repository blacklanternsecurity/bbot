from bbot.modules.base import BaseModule
from bbot.core.errors import InteractshError


class host_header(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Try common HTTP Host header spoofing techniques"}

    in_scope_only = True

    deps_apt = ["curl"]

    def setup(self):
        self.scanned_hosts = set()

        self.subdomain_tags = {}
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.domain = self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning("Interactsh is disabled globally. Interaction based detections will be disabled.")
            self.domain = f"{self.rand_string(12, digits=False)}.com"
        return True

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                match = self.subdomain_tags.get(full_id.split(".")[0])
                if match is None:
                    return
                matched_event = match[0]
                matched_technique = match[1]

                self.emit_event(
                    {
                        "host": str(matched_event.host),
                        "url": matched_event.data["url"],
                        "description": f"Spoofed Host header ({matched_technique}) [{r.get('protocol').upper()}] interaction",
                    },
                    "FINDING",
                    matched_event,
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping results because subdomain tag was missing")

    def finish(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                for r in self.interactsh_instance.poll():
                    self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")

    def cleanup(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    def handle_event(self, event):
        host = f"{event.parsed.scheme}://{event.parsed.netloc}/"
        host_hash = hash(host)
        if host_hash in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
            return
        else:
            self.scanned_hosts.add(host_hash)

        # get any set-cookie responses from the response and add them to the request

        added_cookies = {}

        for header, header_value in event.data["header-dict"].items():
            if header_value.lower() == "set-cookie":
                header_split = header_value.split("=")
                try:
                    added_cookies = {header_split[0]: header_split[1]}
                except IndexError:
                    self.debug(f"failed to parse cookie from string {header_value}")

        domain_reflections = []

        # host header replacement
        technique_description = "standard"
        self.debug(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)
        output = self.helpers.curl(
            url=event.data["url"],
            headers={"Host": f"{subdomain_tag}.{self.domain}"},
            ignore_bbot_global_settings=True,
            cookies=added_cookies,
        )
        if self.domain in output:
            domain_reflections.append(technique_description)

        # absolute URL / Host header transposition
        technique_description = "absolute URL transposition"
        self.debug(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)
        output = self.helpers.curl(
            url=event.data["url"],
            headers={"Host": f"{subdomain_tag}.{self.domain}"},
            path_override=event.data["url"],
            cookies=added_cookies,
        )

        if self.domain in output:
            domain_reflections.append(technique_description)

        # duplicate host header tolerance
        technique_description = "duplicate host header tolerance"
        output = self.helpers.curl(
            url=event.data["url"],
            # Sending a blank HOST first as a hack to trick curl. This makes it no longer an "internal header", thereby allowing for duplicates
            # The fact that it's accepting two host headers is rare enough to note on its own, and not too noisy. Having the 3rd header be an interactsh would result in false negatives for the slightly less interesting cases.
            headers={"Host": ["", str(event.host), str(event.host)]},
            cookies=added_cookies,
            head_mode=True,
        )

        split_output = output.split("\n")
        if " 4" in split_output:
            self.emit_event(
                {
                    "host": str(event.host),
                    "url": event.data["url"],
                    "description": f"Duplicate Host Header Tolerated",
                },
                "FINDING",
                event,
            )

        # host header overrides
        technique_description = "host override headers"
        self.verbose(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)

        override_headers_list = [
            "X-Host",
            "X-Forwarded-Server",
            "X-Forwarded-Host",
            "X-Original-Host",
            "X-Forwarded-For",
            "X-Host",
            "X-HTTP-Host-Override",
            "Forwarded",
        ]
        override_headers = {}
        for oh in override_headers_list:
            override_headers[oh] = f"{subdomain_tag}.{self.domain}"

        output = self.helpers.curl(
            url=event.data["url"],
            headers=override_headers,
            cookies=added_cookies,
        )
        if self.domain in output:
            domain_reflections.append(technique_description)

        # emit all the domain reflections we found
        for dr in domain_reflections:
            self.emit_event(
                {
                    "host": str(event.host),
                    "url": event.data["url"],
                    "description": f"Possible Host header injection. Injection technique: {dr}",
                },
                "FINDING",
                event,
            )
