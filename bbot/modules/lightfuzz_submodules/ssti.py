from .base import BaseLightfuzz

class SSTILightfuzz(BaseLightfuzz):
    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = "<%25%3d%201337*1337%20%25>"
        r = await self.standard_probe(self.event.data["type"], cookies, probe_value)
        if r and "1787569" in r.text:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"POSSIBLE Server-side Template Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Integer Multiplication]",
                }
            )


