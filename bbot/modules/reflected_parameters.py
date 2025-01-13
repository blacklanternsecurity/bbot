from bbot.modules.base import BaseModule


class reflected_parameters(BaseModule):
    watched_events = ["WEB_PARAMETER"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Highlight parameters that reflect their contents in response body",
        "author": "@liquidsec",
        "created_date": "2024-10-29",
    }

    async def handle_event(self, event):
        url = event.data.get("url")
        from_paramminer = str(event.module) == "paramminer_getparams"
        reflection_detected = (
            "http-reflection" in event.tags if from_paramminer else await self.detect_reflection(event, url)
        )

        if reflection_detected:
            description = (
                f"GET Parameter value reflected in response body. Name: [{event.data['name']}] "
                f"Source Module: [{str(event.module)}]"
            )
            if event.data.get("original_value"):
                description += (
                    f" Original Value: [{self.helpers.truncate_string(str(event.data['original_value']), 200)}]"
                )
            data = {"host": str(event.host), "description": description, "url": url}
            await self.emit_event(data, "FINDING", event)

    async def detect_reflection(self, event, url):
        """Detects reflection by sending a probe with a random value and a canary parameter."""
        probe_parameter_name = event.data["name"]
        probe_parameter_value = self.helpers.rand_string()
        canary_parameter_value = self.helpers.rand_string()

        # Add both the probe and canary parameters to the URL
        probe_url = self.helpers.add_get_params(
            url, 
            {
                probe_parameter_name: probe_parameter_value,
                "c4n4ry": canary_parameter_value  # Leet speak for "canary"
            }
        ).geturl()

        probe_response = await self.helpers.request(probe_url, method="GET")

        # Check if the probe parameter value is reflected and the canary is not
        if probe_response:
            response_text = probe_response.text
            reflection_result = (
                probe_parameter_value in response_text and 
                canary_parameter_value not in response_text
            )
            return reflection_result
        return False
