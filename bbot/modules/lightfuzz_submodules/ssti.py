from .base import BaseLightfuzz


class SSTILightfuzz(BaseLightfuzz):
    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        ssti_probes = ["<%25%3d%201337*1337%20%25>","<%= 1337*1337 %>", "${1337*1337}", "%24%7b1337*1337%7d"]
        for probe_value in ssti_probes:
            r = await self.standard_probe(self.event.data["type"], cookies, probe_value, allow_redirects=True)      
            if r and ("1787569" in r.text or "1,787,569" in r.text):
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Server-side Template Injection. {self.metadata()} Detection Method: [Integer Multiplication] Payload: [{probe_value}]",
                    }
                )
                break
