from bbot.errors import InteractshError
from bbot.modules.base import BaseModule


class host_header(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Try common HTTP Host header spoofing techniques",
        "created_date": "2022-07-27",
        "author": "@liquidsec",
    }

    in_scope_only = True
    per_hostport_only = True

    deps_apt = ["curl"]

    async def setup(self):
        self.subdomain_tags = {}
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning("Interactsh is disabled globally. Interaction based detections will be disabled.")
            self.domain = f"{self.rand_string(12, digits=False)}.com"
        return True

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                match = self.subdomain_tags.get(full_id.split(".")[0])
                if match is None:
                    return
                matched_event = match[0]
                matched_technique = match[1]

                protocol = r.get("protocol").upper()
                await self.emit_event(
                    {
                        "host": str(matched_event.host),
                        "url": matched_event.data["url"],
                        "description": f"Spoofed Host header ({matched_technique}) [{protocol}] interaction",
                    },
                    "FINDING",
                    matched_event,
                    context=f"{{module}} spoofed host header and induced {{event.type}}: {protocol} interaction",
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping results because subdomain tag was missing")

    async def finish(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")

    async def cleanup(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def handle_event(self, event):
        # get any set-cookie responses from the response and add them to the request
        url = event.data["url"]

        added_cookies = {}

        for header, header_values in event.data["header-dict"].items():
            for header_value in header_values:
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
        output = await self.helpers.curl(
            url=url,
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
        output = await self.helpers.curl(
            url=url,
            path_override=url,
            cookies=added_cookies,
        )

        if self.domain in output:
            domain_reflections.append(technique_description)

        # duplicate host header tolerance
        technique_description = "duplicate host header tolerance"
        output = await self.helpers.curl(
            url=url,
            # Sending a blank HOST first as a hack to trick curl. This makes it no longer an "internal header", thereby allowing for duplicates
            # The fact that it's accepting two host headers is rare enough to note on its own, and not too noisy. Having the 3rd header be an interactsh would result in false negatives for the slightly less interesting cases.
            headers={"Host": ["", str(event.host), str(event.host)]},
            cookies=added_cookies,
            head_mode=True,
        )

        split_output = output.split("\n")
        if " 4" in split_output:
            description = f"Duplicate Host Header Tolerated"
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "description": description,
                },
                "FINDING",
                event,
                context=f"{{module}} scanned {event.data['url']} and identified {{event.type}}: {description}",
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

        output = await self.helpers.curl(
            url=url,
            headers=override_headers,
            cookies=added_cookies,
        )
        if self.domain in output:
            domain_reflections.append(technique_description)

        # emit all the domain reflections we found
        for dr in domain_reflections:
            description = f"Possible Host header injection. Injection technique: {dr}"
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "description": description,
                },
                "FINDING",
                event,
                context=f"{{module}} scanned {url} and identified {{event.type}}: {description}",
            )
