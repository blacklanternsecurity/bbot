from .base import BaseAccessBypass, Probe

# Side-effect-free verbs. HEAD/OPTIONS can't modify state; an unknown verb (ACB) is routed as GET
# by servers that don't recognize it, bypassing GET-specific deny rules without touching anything.
safe_methods = ["HEAD", "OPTIONS", "ACB"]

# State-changing verbs. Only sent when `state_changing_methods` is enabled (makes the module invasive).
state_changing_verbs = ["POST", "PUT", "PATCH", "DELETE"]

# Headers that rewrite the effective method at the application layer while the wire verb stays POST.
# A POST on the wire may trigger actions, so these are gated behind `state_changing_methods` too.
override_headers = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]


class method(BaseAccessBypass):
    friendly_name = "Method Manipulation"

    def probes(self):
        url = f"{self.base_url}/{self.parsed_url.path.lstrip('/')}"
        sibling = f"{self.base_url}/{self.helpers.rand_string(8, digits=False)}"
        sibling_2 = f"{self.base_url}/{self.helpers.rand_string(8, digits=False)}"

        verbs = list(safe_methods)
        state_changing = self.access_bypass.config.get("state_changing_methods", False)
        if state_changing:
            verbs += state_changing_verbs

        for verb in verbs:
            yield Probe(
                key=f"method:{verb}",
                label=f"Modified Method: {verb}",
                url=url,
                method=verb,
                sibling_url=sibling,
                sibling_url_2=sibling_2,
            )
        if state_changing:
            for header in override_headers:
                yield Probe(
                    key=f"override:{header}",
                    label=f"Added Header: {header}: GET (POST)",
                    url=url,
                    method="POST",
                    headers={header: "GET"},
                    sibling_url=sibling,
                    sibling_url_2=sibling_2,
                )
