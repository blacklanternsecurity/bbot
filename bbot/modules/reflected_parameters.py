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
        reflection_detected = await self.detect_reflection(event, url)

        if reflection_detected:
            param_type = event.data.get("type", "UNKNOWN")
            description = (
                f"[{param_type}] Parameter value reflected in response body. Name: [{event.data['name']}] "
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
        probe_response = await self.send_probe_with_canary(
            event,
            probe_parameter_name,
            probe_parameter_value,
            canary_parameter_value,
            cookies=event.data.get("assigned_cookies", {}),
            timeout=10,
        )

        # Check if the probe parameter value is reflected AND the canary is not
        if probe_response:
            response_text = probe_response.text
            reflection_result = probe_parameter_value in response_text and canary_parameter_value not in response_text
            return reflection_result
        return False

    async def send_probe_with_canary(self, event, parameter_name, parameter_value, canary_value, cookies, timeout=10):
        method = "GET"
        url = event.data["url"]
        headers = {}
        data = None
        json_data = None
        params = {parameter_name: parameter_value, "c4n4ry": canary_value}

        if event.data["type"] == "GETPARAM":
            url = f"{url}?{parameter_name}={parameter_value}&c4n4ry={canary_value}"
        elif event.data["type"] == "COOKIE":
            cookies.update(params)
        elif event.data["type"] == "HEADER":
            headers.update(params)
        elif event.data["type"] == "POSTPARAM":
            method = "POST"
            data = params
        elif event.data["type"] == "BODYJSON":
            method = "POST"
            json_data = params

        self.debug(
            f"Sending {method} request to {url} with headers: {headers}, cookies: {cookies}, data: {data}, json: {json_data}"
        )

        response = await self.helpers.request(
            method=method, url=url, headers=headers, cookies=cookies, data=data, json=json_data, timeout=timeout
        )
        return response
