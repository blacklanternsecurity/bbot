from .base import BaseLightfuzz


class ssti(BaseLightfuzz):
    """
    Detects server-side template injection vulnerabilities.

    Techniques:

    * Arithmetic Evaluation:
       - Injects encoded and unencoded multiplication expressions to detect evaluation
    """

    friendly_name = "Server-side Template Injection"

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        # These are common SSTI payloads, each attempting to trigger an integer multiplication which would produce an expected value
        ssti_probes = [
            "<%25%3d%201337*1337%20%25>",
            "<%= 1337*1337 %>",
            "${1337*1337}",
            "%24%7b1337*1337%7d",
            "1,787{{z}},569",
        ]
        for probe_value in ssti_probes:
            r = await self.standard_probe(
                self.event.data["type"], cookies, probe_value, allow_redirects=True, skip_urlencoding=True
            )

            # look for the expected value in the response
            if r and ("1787569" in r.text or "1,787,569" in r.text):
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Server-side Template Injection. {self.metadata()} Detection Method: [Integer Multiplication] Payload: [{probe_value}]",
                    }
                )
                break
