from .base import BaseLightfuzz


class ssrf(BaseLightfuzz):
    """
    Detects Server-Side Request Forgery (SSRF) vulnerabilities.

    Techniques:

    * OOB (Out-of-Band) Detection:
       - Injects URLs pointing to an Interactsh server as parameter values
       - Tries multiple URL schemes (http://, https://)
       - Detects SSRF through DNS/HTTP interaction callbacks via Interactsh
    """

    friendly_name = "Server-Side Request Forgery"
    uses_interactsh = True

    async def fuzz(self):
        if not self.lightfuzz.interactsh_instance:
            return

        cookies = self.event.data.get("assigned_cookies", {})
        # Try with explicit schemes and bare domain (for cases where the server prepends the scheme)
        prefixes = ["http://", "https://", ""]

        for prefix in prefixes:
            probe_label = prefix if prefix else "no scheme"
            _, host = self.register_interactsh_tag(
                name="Server-Side Request Forgery",
                description=f"Server-Side Request Forgery (OOB Interaction) Type: [{self.event.data['type']}] Parameter Name: [{self.event.data['name']}] Probe: [{probe_label}]",
                severity="HIGH",
                confidence="CONFIRMED",
                severity_dns="HIGH",
                confidence_dns="MEDIUM",
            )
            await self.standard_probe(
                self.event.data["type"],
                cookies,
                f"{prefix}{host}",
                timeout=15,
            )
