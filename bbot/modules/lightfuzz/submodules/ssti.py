from .base import BaseLightfuzz


class ssti(BaseLightfuzz):
    """
    Detects server-side template injection vulnerabilities.

    Techniques:

    * Arithmetic Evaluation:
       - Injects encoded and unencoded multiplication expressions to detect evaluation
       - Covers ERB/JSP, EL/Freemarker/Mako, Jinja2/Twig (both the
         direct `{{1337*1337}}` form and the `1,787{{z}},569` comma-
         collapse trick for engines that render `{{undefined}}` as ""),
         and Smarty (single-brace)
       - Baseline-gated: suppresses findings when the canary product
         already appears in the unaltered response, which eliminates the
         rare coincidental-number false positive
    """

    friendly_name = "Server-side Template Injection"

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})

        # Baseline: the current response without any template syntax in the
        # value. If the detection canary (`1787569` or `1,787,569`) already
        # appears here, later matches are ambiguous and we should not flag.
        probe_value = self.incoming_probe_value(populate_empty=True)
        baseline = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, allow_redirects=True, skip_urlencoding=True
        )
        if baseline is None:
            self.debug("baseline request failed, aborting ssti detection")
            return
        baseline_text = baseline.text
        if "1787569" in baseline_text or "1,787,569" in baseline_text:
            self.debug(
                "canary value already present in baseline response; suppressing ssti detection "
                "to avoid a coincidental-number false positive"
            )
            return

        # Common SSTI payloads across template engines. Each attempts to
        # trigger 1337*1337 = 1787569.
        ssti_probes = [
            "<%25%3d%201337*1337%20%25>",  # URL-encoded ERB/JSP `<%= 1337*1337 %>`
            "<%= 1337*1337 %>",  # ERB/JSP
            "${1337*1337}",  # EL / Freemarker / Thymeleaf / Mako
            "%24%7b1337*1337%7d",  # URL-encoded ${1337*1337}
            "{{1337*1337}}",  # Jinja2 / Twig / Tornado / Django-template
            "1,787{{z}},569",  # Jinja2 comma-collapse (legacy, still useful)
            "{1337*1337}",  # Smarty single-brace
            # Apache Velocity uses `#set($x=A*B)$x`. The `#` must be
            # URL-encoded to avoid being interpreted as a URL fragment.
            "%23set(%24x%3d1337*1337)%24x",
        ]
        for probe_value in ssti_probes:
            r = await self.standard_probe(
                self.event.data["type"], cookies, probe_value, allow_redirects=True, skip_urlencoding=True
            )

            if r and ("1787569" in r.text or "1,787,569" in r.text):
                self.results.append(
                    {
                        "name": "Possible Server-side Template Injection",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": f"POSSIBLE Server-side Template Injection. {self.metadata()} Detection Method: [Integer Multiplication] Payload: [{probe_value}]",
                    }
                )
                break
