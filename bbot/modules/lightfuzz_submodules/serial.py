from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class SerialLightfuzz(BaseLightfuzz):
    """
    This module finds places where serialized objects are being deserialized.

    It tests two possible deserialization cases. It starts by performing a baseline with a specially-crafted non-serialized payload, which successfully decodes via both base64 and hex. This is designed to coax out an error that's not decoding-specific.

    After performing the baseline (Which by design may contain an error), we check for two possible deserialization cases:
        - Replacing the payload with a serialized object changes the status code to 200 (minus some string signatures to help prevent false positives)
        - If the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
            - Because of the possibility for false positives, we only consider responses that are 500s 200s where the body changed.
    """

    def is_possibly_serialized(self, value):
        # Use the is_base64 method from BaseLightfuzz via self
        if self.is_base64(value):
            return True

        # Use the is_hex method from BaseLightfuzz via self
        if self.is_hex(value):
            return True

        # List of common PHP serialized data prefixes
        php_serialized_prefixes = [
            "a:",  # Array
            "O:",  # Object
            "s:",  # String
            "i:",  # Integer
            "d:",  # Double
            "b:",  # Boolean
            "N;",  # Null
        ]

        # Check if the value starts with any of the PHP serialized prefixes
        if any(value.startswith(prefix) for prefix in php_serialized_prefixes):
            return True
        return False

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        control_payload = "DEADBEEFCAFEBABE1234567890ABCDEF"
        # These payloads are benign, no-op, or otherwise harmless
        #  minimally sized valid serialized objects for their given language/platform
        serialization_payloads = {
            "php_base64": "YTowOnt9",
            "php_raw": "a:0:{}",
            "java_hex": "ACED00057372000E6A6176612E6C616E672E426F6F6C65616ECD207EC0D59CF6EE02000157000576616C7565787000",
            "java_base64": "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cAA=",
            "java_base64_string_error": "rO0ABXQABHRlc3Q=",
            "java_base64_OptionalDataException": "rO0ABXcEAAAAAAEAAAABc3IAEGphdmEudXRpbC5IYXNoTWFwAAAAAAAAAAECAAJMAARrZXkxYgABAAAAAAAAAAJ4cHcBAAAAB3QABHRlc3Q=",
            "java_hex_OptionalDataException": "ACED0005737200106A6176612E7574696C2E486173684D617000000000000000012000014C00046B6579317A00010000000000000278707000000774000474657374",
            "dotnet_hex": "0001000000ffffffff01000000000000000601000000076775737461766f0b",
            "dotnet_base64": "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==",
            "ruby_base64": "BAh7BjoKbE1FAAVJsg==",
        }

        serialization_errors = [
            "invalid user",
            "cannot cast java.lang.string",
            "dump format error",
            "java.io.optionaldataexception",
        ]

        general_errors = [
            "Internal Error",
            "Internal Server Error",
            "The requested URL was rejected",
        ]

        probe_value = self.incoming_probe_value(populate_empty=False)
        if probe_value:
            if self.is_possibly_serialized(probe_value):
                self.lightfuzz.debug(
                    f"Existing value is not ruled out for being a serialized object, proceeding [{self.event.data['type']}] [{self.event.data['name']}]"
                )
            else:
                self.lightfuzz.debug(
                    f"The Serialization Submodule only operates when there is no original value, or when the original value could potentially be a serialized object, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
                )
                return

        # Obtain a baseline and with limited retries for failure
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                http_compare = self.compare_baseline(self.event.data["type"], control_payload, cookies)
                baseline_probe = await self.compare_probe(http_compare, self.event.data["type"], control_payload, cookies)

                if baseline_probe[0] is True:
                    self.lightfuzz.debug(f"lightfuzz[serial]: Consistent baseline confirmed on attempt {str(attempt + 1)}")
                    break
                else:
                    self.lightfuzz.debug(f"lightfuzz[serial]: Inconsistent baseline on attempt {str(attempt + 1)}")
                    if attempt == max_attempts - 1:
                        self.lightfuzz.warning(
                            "lightfuzz[serial]: Failed to confirm consistent baseline after 3 attempts, aborting"
                        )
                        return
            except HttpCompareError as e:
                self.lightfuzz.debug(f"HttpCompareError encountered: {e}")
                continue    

        # Proceed with payload probes
        for type, payload in serialization_payloads.items():
            try:
                matches_baseline, diff_reasons, reflection, response = await self.compare_probe(
                    http_compare, self.event.data["type"], payload, cookies
                )
            except HttpCompareError as e:
                self.lightfuzz.debug(f"HttpCompareError encountered: {e}")
                continue

            if matches_baseline:
                self.lightfuzz.debug(f"Payload {type} matches baseline, skipping")
                continue

            self.lightfuzz.debug(f"Probe result for {type}: {response}")

            status_code = getattr(response, "status_code", 0)
            if status_code == 0:
                continue

            if diff_reasons == ["header"]:
                self.lightfuzz.debug(f"Only header diffs found for {type}, skipping")
                continue

            if status_code not in (200, 500):
                self.lightfuzz.debug(f"Status code {status_code} not in (200, 500), skipping")
                continue

            # if the status code changed to 200, and the response doesn't match our general error exclusions, we have a finding
            self.lightfuzz.debug(f"Potential finding detected for {type}, needs confirmation")
            if (
                status_code == 200
                and "code" in diff_reasons
                and not any(
                    error in response.text for error in general_errors
                )  # ensure the 200 is not actually an error
            ):
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Error Resolution] Serialization Payload: [{type}]",
                    }
                )
            # if the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
            # but only if the response is a 500, or a 200 with a body diff
            elif status_code == 500 or (status_code == 200 and diff_reasons == ["body"]):
                self.lightfuzz.debug(f"500 status code or body match for {type}")
                for serialization_error in serialization_errors:
                    if serialization_error in response.text.lower():
                        self.lightfuzz.debug(f"Error string '{serialization_error}' found in response for {type}")
                        self.results.append(
                            {
                                "type": "FINDING",
                                "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Differential Error Analysis] Error-String: [{serialization_error}] Payload: [{type}]",
                            }
                        )
                        break
