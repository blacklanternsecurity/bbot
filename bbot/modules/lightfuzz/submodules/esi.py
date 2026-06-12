from .base import BaseLightfuzz


class esi(BaseLightfuzz):
    """
    Detects Edge Side Includes (ESI) processing vulnerabilities.

    Two complementary techniques that run independently:

    * Tag-strip Detection (original):
       - Sends `AA<!--esi-->BB<!--esx-->CC` and checks if `<!--esi-->`
         was stripped. Proves the edge processes ESI comment tags.
         MEDIUM severity, HIGH confidence.

    * Remote-Include OOB Confirmation (new):
       - Sends `<esi:include src="http://{interactsh}/"/>`. If the edge
         actually FETCHES the include, interactsh observes the callback
         and emits a CRITICAL CONFIRMED finding. Stronger than tag-
         stripping: tag-stripping can happen cosmetically; a remote
         fetch proves real processing with exploitable side effects.
    """

    # Technique lifted from https://github.com/PortSwigger/active-scan-plus-plus

    friendly_name = "Edge Side Includes"
    uses_interactsh = True

    async def check_probe(self, cookies, probe, match):
        """
        Sends the probe and checks if the expected match string is found in the response.
        """
        probe_result = await self.standard_probe(self.event.data["type"], cookies, probe)
        if probe_result and match in probe_result.text:
            self.results.append(
                {
                    "type": "FINDING",
                    "name": "Edge Side Include Processing",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "description": f"Edge Side Include. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}]{self.conversion_note()}",
                }
            )
            return True
        return False

    async def fuzz(self):
        """
        Main fuzzing method that sends the ESI test payload and checks for processing.
        """
        cookies = self.event.data.get("assigned_cookies", {})

        # Tag-strip detection (original technique). If ESI is processed,
        # <!--esi--> gets removed, leaving AABB<!--esx-->CC in the response.
        payload = "AA<!--esi-->BB<!--esx-->CC"
        detection_string = "AABB<!--esx-->CC"
        await self.check_probe(cookies, payload, detection_string)

        # Remote-include OOB confirmation (new). Runs alongside the
        # tag-strip probe — they detect distinct signals and both can
        # fire on the same parameter. bbot's scope model prevents the
        # interactsh URL from being self-fetched if it gets reflected
        # into the response body (out-of-scope host, not fetched).
        if self.lightfuzz.interactsh_instance:
            _, host = self.register_interactsh_tag(
                name="Edge Side Include Remote Fetch",
                description=(
                    f"Edge Side Include Remote Fetch (OOB Interaction) "
                    f"Parameter: [{self.event.data['name']}] "
                    f"Parameter Type: [{self.event.data['type']}]{self.conversion_note()}"
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
            )
            include_payload = f'<esi:include src="http://{host}/"/>'
            await self.standard_probe(
                self.event.data["type"],
                cookies,
                include_payload,
                timeout=15,
            )
