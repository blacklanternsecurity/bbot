from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class serial(BaseLightfuzz):
    """Finds parameters where serialized objects might be being deserialized.
    It starts by performing a baseline with a specially-crafted non-serialized payload, separated by type (base64, hex, php raw).
    This is designed to coax out an error that's not related to the decoding process.

    After performing the baseline (Which by design may contain an error), we check for two possible deserialization cases:

        1) Replacing the payload with a serialized object changes the status code to 200 (minus some string signatures to help prevent false positives)

        2) If the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
    """

    friendly_name = "Unsafe Deserialization"

    # Class-level constants
    CONTROL_PAYLOAD_HEX = "f56124208220432ec767646acd2e6c6bc9622a62c5656f2eeb616e2f"
    CONTROL_PAYLOAD_BASE64 = "4Wt5fYx5Y3rELn5myS5oa996Ji7IZ28uwGdha4x6YmuMfG992CA="
    CONTROL_PAYLOAD_PHP_RAW = "z:0:{}"

    BASE64_SERIALIZATION_PAYLOADS = {
        "php_base64": "YToxOntpOjA7aToxO30=",
        "java_base64": "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cAA=",
        "java_base64_string_error": "rO0ABXQABHRlc3Q=",
        "java_base64_OptionalDataException": "rO0ABXcEAAAAAAEAAAABc3IAEGphdmEudXRpbC5IYXNoTWFwAAAAAAAAAAECAAJMAARrZXkxYgABAAAAAAAAAAJ4cHcBAAAAB3QABHRlc3Q=",
        "dotnet_base64": "AAEAAAD/////AQAAAAAAAAAGAQAAAAdndXN0YXZvCw==",
        "ruby_base64": "BAh7BjoKbE1FAAVJsg==",
    }

    HEX_SERIALIZATION_PAYLOADS = {
        "java_hex": "ACED00057372000E6A6176612E6C616E672E426F6F6C65616ECD207EC0D59CF6EE02000157000576616C7565787000",
        "java_hex_OptionalDataException": "ACED0005737200106A6176612E7574696C2E486173684D617000000000000000012000014C00046B6579317A00010000000000000278707000000774000474657374",
        "dotnet_hex": "0001000000ffffffff01000000000000000601000000076775737461766f0b",
    }

    PHP_RAW_SERIALIZATION_PAYLOADS = {
        "php_raw": "a:0:{}",
    }

    SERIALIZATION_ERRORS = [
        "invalid user",
        "cannot cast java.lang.string",
        "dump format error",
        "java.io.optionaldataexception",
    ]

    GENERAL_ERRORS = [
        "Internal Error",
        "Internal Server Error",
        "The requested URL was rejected",
    ]

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
        control_payload_hex = self.CONTROL_PAYLOAD_HEX
        control_payload_base64 = self.CONTROL_PAYLOAD_BASE64
        control_payload_php_raw = self.CONTROL_PAYLOAD_PHP_RAW

        base64_serialization_payloads = self.BASE64_SERIALIZATION_PAYLOADS
        hex_serialization_payloads = self.HEX_SERIALIZATION_PAYLOADS
        php_raw_serialization_payloads = self.PHP_RAW_SERIALIZATION_PAYLOADS

        serialization_errors = self.SERIALIZATION_ERRORS
        general_errors = self.GENERAL_ERRORS

        probe_value = self.incoming_probe_value(populate_empty=False)
        if probe_value:
            if self.is_possibly_serialized(probe_value):
                self.debug(
                    f"Existing value is not ruled out for being a serialized object, proceeding [{self.event.data['type']}] [{self.event.data['name']}]"
                )
            else:
                self.debug(
                    f"The Serialization Submodule only operates when there is no original value, or when the original value could potentially be a serialized object, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
                )
                return

        try:
            http_compare_hex = self.compare_baseline(self.event.data["type"], control_payload_hex, cookies)
            http_compare_base64 = self.compare_baseline(self.event.data["type"], control_payload_base64, cookies)
            http_compare_php_raw = self.compare_baseline(self.event.data["type"], control_payload_php_raw, cookies)
        except HttpCompareError as e:
            self.debug(f"HttpCompareError encountered: {e}")
            return

        # Proceed with payload probes
        for payload_set, payload_baseline in [
            (base64_serialization_payloads, http_compare_base64),
            (hex_serialization_payloads, http_compare_hex),
            (php_raw_serialization_payloads, http_compare_php_raw),
        ]:
            for type, payload in payload_set.items():
                try:
                    matches_baseline, diff_reasons, reflection, response = await self.compare_probe(
                        payload_baseline, self.event.data["type"], payload, cookies
                    )
                except HttpCompareError as e:
                    self.debug(f"HttpCompareError encountered: {e}")
                    continue

                if matches_baseline:
                    self.debug(f"Payload {type} matches baseline, skipping")
                    continue

                self.debug(f"Probe result for {type}: {response}")

                status_code = getattr(response, "status_code", 0)
                if status_code == 0:
                    continue

                if diff_reasons == ["header"]:
                    self.debug(f"Only header diffs found for {type}, skipping")
                    continue

                if status_code not in (200, 500):
                    self.debug(f"Status code {status_code} not in (200, 500), skipping")
                    continue

                # if the status code changed to 200, and the response doesn't match our general error exclusions, we have a finding
                self.debug(f"Potential finding detected for {type}, needs confirmation")
                if (
                    status_code == 200
                    and "code" in diff_reasons
                    and not any(
                        error in response.text for error in general_errors
                    )  # ensure the 200 is not actually an error
                ):

                    def get_title(text):
                        soup = self.lightfuzz.helpers.beautifulsoup(text, "html.parser")
                        if soup and soup.title and soup.title.string:
                            return f"'{self.lightfuzz.helpers.truncate_string(soup.title.string, 50)}'"
                        return ""

                    baseline_title = get_title(payload_baseline.baseline.text)
                    probe_title = get_title(response.text)

                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Error Resolution (Baseline: [{payload_baseline.baseline.status_code}] {baseline_title} -> Probe: [{status_code}] {probe_title})] Serialization Payload: [{type}]",
                        }
                    )
                # if the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
                # but only if the response is a 500, or a 200 with a body diff
                elif status_code == 500 or (status_code == 200 and diff_reasons == ["body"]):
                    self.debug(f"500 status code or body match for {type}")
                    for serialization_error in serialization_errors:
                        # check for the error string, but also ensure the error string isn't just always present in the response
                        if (
                            serialization_error in response.text.lower()
                            and serialization_error not in payload_baseline.baseline.text.lower()
                        ):
                            self.debug(f"Error string '{serialization_error}' found in response for {type}")
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Differential Error Analysis] Error-String: [{serialization_error}] Payload: [{type}]",
                                }
                            )
                            break
