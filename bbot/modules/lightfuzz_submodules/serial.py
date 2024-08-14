from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class SerialLightfuzz(BaseLightfuzz):
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

        original_value = self.event.data.get("original_value", None)
        if not (original_value == None or original_value == ""):
            self.lightfuzz.debug(
                f"The Serialization Submodule only operates when there if no original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        http_compare = self.compare_baseline(self.event.data["type"], control_payload, cookies)
        for type, payload in serialization_payloads.items():
            try:
                serialization_probe = await self.compare_probe(http_compare, self.event.data["type"], payload, cookies)
                if serialization_probe[0] == False and serialization_probe[1] != ["header"]:
                    if serialization_probe[3].status_code == 200 and "code" in serialization_probe[1]:
                        self.results.append(
                            {
                                "type": "FINDING",
                                "description": f"POSSIBLE Unsafe Deserialization. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Technique: [Error Resolution] Serialization Payload: [{type}]",
                            }
                        )
                    elif serialization_probe[3].status_code == 500 or (
                        serialization_probe[3].status_code == 200 and serialization_probe[1] == ["body"]
                    ):
                        for serialization_error in serialization_errors:
                            if serialization_error in serialization_probe[3].text.lower():
                                self.results.append(
                                    {
                                        "type": "FINDING",
                                        "description": f"POSSIBLE Unsafe Deserialization. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Technique: [Differential Error Analysis] Error-String: [{serialization_error}] Payload: [{type}]",
                                    }
                                )
                                break
            except HttpCompareError as e:
                self.lightfuzz.debug(e)
                continue
