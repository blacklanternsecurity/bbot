from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
import base64
import binascii


class SerialLightfuzz(BaseLightfuzz):


    def is_possibly_serialized(self, value):
        # List of common PHP serialized data prefixes
        php_serialized_prefixes = [
            'a:',  # Array
            'O:',  # Object
            's:',  # String
            'i:',  # Integer
            'd:',  # Double
            'b:',  # Boolean
            'N;',  # Null
        ]

        try:
            # Check if the value is valid Base64
            if base64.b64encode(base64.b64decode(value)).decode() == value:
                return True
        except (binascii.Error, UnicodeDecodeError):
            pass

        try:
            # Check if the value is valid hexadecimal
            if binascii.hexlify(binascii.unhexlify(value)).decode() == value:
                return True
        except (binascii.Error, UnicodeDecodeError):
            pass

        # Check if the value starts with any of the PHP serialized prefixes
        if any(value.startswith(prefix) for prefix in php_serialized_prefixes):
            return True
        return False

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        control_payload = "DEADBEEFCAFEBABE1234567890ABCDEF"
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

        http_compare = self.compare_baseline(self.event.data["type"], control_payload, cookies)
        for type, payload in serialization_payloads.items():
            try:
                serialization_probe = await self.compare_probe(http_compare, self.event.data["type"], payload, cookies)
                self.lightfuzz.debug(f"Probe result for {type}: {serialization_probe}")

                if serialization_probe[0] is False and serialization_probe[1] != ["header"]:
                    self.lightfuzz.debug(f"Potential finding detected for {type}, needs confirmation")
                    if (
                        serialization_probe[3].status_code == 200
                        and "code" in serialization_probe[1]
                        and not any(error in serialization_probe[3].text for error in general_errors) # ensure the 200 is not actually an error
                    ):
                        self.results.append(
                            {
                                "type": "FINDING",
                                "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Error Resolution] Serialization Payload: [{type}]",
                            }
                        )
                    elif serialization_probe[3].status_code == 500 or (
                        serialization_probe[3].status_code == 200 and serialization_probe[1] == ["body"]
                    ):
                        self.lightfuzz.debug(f"500 status code or body match for {type}")
                        for serialization_error in serialization_errors:
                            if serialization_error in serialization_probe[3].text.lower():
                                self.lightfuzz.debug(f"Error string '{serialization_error}' found in response for {type}")
                                self.results.append(
                                    {
                                        "type": "FINDING",
                                        "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Differential Error Analysis] Error-String: [{serialization_error}] Payload: [{type}]",
                                    }
                                )
                                break
            except HttpCompareError as e:
                self.lightfuzz.debug(f"HttpCompareError encountered: {e}")
                continue

