import base64
import hashlib
from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
from urllib.parse import unquote, quote


class CryptoLightfuzz(BaseLightfuzz):

    @staticmethod
    def is_hex(s):
        try:
            bytes.fromhex(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_base64(s):
        try:
            if base64.b64encode(base64.b64decode(s)).decode() == s:
                return True
        except Exception:

            return False
        return False

    crypto_error_strings = [
        "invalid mac",
        "padding is invalid and cannot be removed",
        "bad data",
        "length of the data to decrypt is invalid",
        "specify a valid key size",
        "invalid algorithm specified",
        "object already exists",
        "key does not exist",
        "the parameter is incorrect",
        "cryptography exception",
        "access denied",
        "unknown error",
        "invalid provider type",
        "no valid cert found",
        "cannot find the original signer",
        "signature description could not be created",
        "crypto operation failed",
        "OpenSSL Error",
    ]

    @staticmethod
    def format_agnostic_decode(input_string):
        encoding = "unknown"
        decoded_input = unquote(input_string)
        if CryptoLightfuzz.is_hex(decoded_input):
            data = bytes.fromhex(decoded_input)
            encoding = "hex"
        elif CryptoLightfuzz.is_base64(decoded_input):
            data = base64.b64decode(decoded_input)
            encoding = "base64"
        else:
            data = str
        return data, encoding

    @staticmethod
    def format_agnostic_encode(data, encoding, urlencode=True):
        if encoding == "hex":
            encoded_data = data.hex()
        elif encoding == "base64":
            encoded_data = base64.b64encode(data).decode("utf-8")  # base64 encoding returns bytes, decode to string
        else:
            raise ValueError("Unsupported encoding type specified")

        if urlencode:
            return quote(encoded_data)
        return encoded_data

    @staticmethod
    def modify_string(input_string, action="truncate", position=None, extension_length=1):

        if not isinstance(input_string, str):
            input_string = str(input_string)

        data, encoding = CryptoLightfuzz.format_agnostic_decode(input_string)
        if encoding != "base64" and encoding != "hex":
            raise ValueError("Input must be either hex or base64 encoded")

        if action == "truncate":
            modified_data = data[:-1]  # Remove the last byte
        elif action == "mutate":
            if not position:
                position = len(data) // 2
            if position < 0 or position >= len(data):
                raise ValueError("Position out of range")
            byte_list = list(data)
            byte_list[position] = (byte_list[position] + 1) % 256
            modified_data = bytes(byte_list)
        elif action == "extend":
            modified_data = data + (b"\x00" * extension_length)
        elif action == "flip":
            if not position:
                position = len(data) // 2
            if position < 0 or position >= len(data):
                raise ValueError("Position out of range")
            byte_list = list(data)
            byte_list[position] ^= 0xFF  # Flip all bits in the byte at the specified position
            modified_data = bytes(byte_list)
        else:
            raise ValueError("Unsupported action")
        return CryptoLightfuzz.format_agnostic_encode(modified_data, encoding)

    def is_likely_encrypted(self, data, threshold=4.5):
        entropy = self.lightfuzz.helpers.calculate_entropy(data)
        return entropy >= threshold

    def cryptanalysis(self, input_string):
        likely_crypto = False
        possible_block_cipher = False
        data, encoding = self.format_agnostic_decode(input_string)
        likely_crypto = self.is_likely_encrypted(data)
        data_length = len(data)
        if data_length % 8 == 0:
            possible_block_cipher = True
        return likely_crypto, possible_block_cipher

    @staticmethod
    def possible_block_sizes(ciphertext_length):
        potential_block_sizes = [8, 16]
        possible_sizes = []
        for block_size in potential_block_sizes:
            num_blocks = ciphertext_length / block_size
            if num_blocks.is_integer() and num_blocks >= 2:
                possible_sizes.append(block_size)
        return possible_sizes

    async def padding_oracle_execute(self, original_data, encoding, cookies, possible_first_byte=False):

        possible_block_sizes = self.possible_block_sizes(len(original_data))

        for block_size in possible_block_sizes:
            ivblock = b"\x00" * block_size
            paddingblock = b"\x00" * block_size
            datablock = original_data[-block_size:]
            if possible_first_byte:
                baseline_byte = b"\xFF"
                starting_pos = 0
            else:
                baseline_byte = b"\x00"
                starting_pos = 1

            baseline = self.compare_baseline(
                self.event.data["type"], ivblock + paddingblock[:-1] + baseline_byte + datablock, cookies
            )
            differ_count = 0
            for i in range(starting_pos, starting_pos + 254):
                byte = bytes([i])
                oracle_probe = await self.compare_probe(
                    baseline,
                    self.event.data["type"],
                    self.format_agnostic_encode(ivblock + paddingblock[:-1] + byte + datablock, encoding),
                    cookies,
                )

                if oracle_probe[0] == False and "body" in oracle_probe[1]:
                    differ_count += 1
                    if i == 1:
                        possible_first_byte = True
                        continue
                    elif i == 2 and possible_first_byte == True:
                        # Thats two results which appear "different". Its entirely possible \x00 was the correct padding. We will break from this loop and redo it with the last byte as the baseline instead of the first
                        return False, None
            if differ_count == 1:
                return True, block_size
            else:
                continue
        return False, None

    async def padding_oracle(self, probe_value, cookies):
        data, encoding = self.format_agnostic_decode(probe_value)

        padding_oracle_result, block_size = await self.padding_oracle_execute(data, encoding, cookies)
        if padding_oracle_result == None:
            self.lightfuzz.debug("ended up in possible_first_byte situation - retrying with different first byte")
            padding_oracle_result = await self.padding_oracle_execute(
                data, encoding, cookies, possible_first_byte=True
            )

        if padding_oracle_result == True:
            context = f"Lightfuzz Cryptographic Probe Submodule detected a probable padding oracle vulnerability after manipulating parameter: [{self.event.data['name']}]"
            self.results.append(
                {
                    "type": "VULNERABILITY",
                    "severity": "HIGH",
                    "description": f"Padding Oracle Vulnerability. Block size: [{str(block_size)}] {self.metadata()}",
                    "context": context,
                }
            )

    async def error_string_search(self, text_dict, baseline_text):

        matching_techniques = set()
        matching_strings = set()

        for label, text in text_dict.items():
            matched_strings = self.lightfuzz.helpers.string_scan(self.crypto_error_strings, text)
            for m in matched_strings:
                matching_strings.add(m)
            matching_techniques.add(label)
        context = f"Lightfuzz Cryptographic Probe Submodule detected a cryptographic error after manipulating parameter: [{self.event.data['name']}]"
        if len(matching_strings) > 0:
            false_positive_check = self.lightfuzz.helpers.string_scan(self.crypto_error_strings, baseline_text)
            false_positive_matches = set(matched_strings) & set(false_positive_check)
            if not false_positive_matches:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"Possible Cryptographic Error. {self.metadata()} Strings: [{','.join(matching_strings)}] Detection Technique(s): [{','.join(matching_techniques)}]",
                        "context": context,
                    }
                )
            self.lightfuzz.debug(
                f"Aborting cryptographic error reporting - baseline_text already contained detected string(s) ({','.join(false_positive_check)})"
            )

    @staticmethod
    def identify_hash_function(hash_bytes):
        hash_length = len(hash_bytes)
        hash_functions = {
            16: hashlib.md5,
            20: hashlib.sha1,
            32: hashlib.sha256,
            48: hashlib.sha384,
            64: hashlib.sha512,
        }

        if hash_length in hash_functions:
            return hash_functions[hash_length]

    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.probe_value_incoming(populate_empty=False)
        if not probe_value:
            self.lightfuzz.debug(
                f"The Cryptography Probe Submodule requires original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        baseline_probe = await self.baseline_probe(cookies)
        if not baseline_probe:
            self.lightfuzz.warning(f"Couldn't get baseline_probe for url {self.event.data['url']}, aborting")
            return

        try:
            truncate_probe_value = self.modify_string(probe_value, action="truncate")
            mutate_probe_value = self.modify_string(probe_value, action="mutate")
        except ValueError as e:
            self.lightfuzz.debug(
                f"Encountered error modifying value for parameter {self.event.data['name']}: {e} , aborting"
            )
            return

        # Basic crypanalysis
        likely_crypto, possible_block_cipher = self.cryptanalysis(unquote(probe_value))

        if not likely_crypto:
            self.lightfuzz.debug("Parameter value does not appear to be cryptographic, aborting tests")
            return

        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)

        # Cryptographic Response Divergence Test
        try:
            arbitrary_probe = await self.compare_probe(http_compare, self.event.data["type"], "AAAAAAA", cookies)
            truncate_probe = await self.compare_probe(
                http_compare, self.event.data["type"], truncate_probe_value, cookies
            )
            mutate_probe = await self.compare_probe(http_compare, self.event.data["type"], mutate_probe_value, cookies)
        except HttpCompareError as e:
            self.lightfuzz.warning(f"Encountered HttpCompareError Sending Compare Probe: {e}")
            return

        confirmed_techniques = []
        if mutate_probe[0] == False and "body" in mutate_probe[1]:
            if (http_compare.compare_body(mutate_probe[3].text, arbitrary_probe[3].text) == False) or mutate_probe[
                3
            ].text == "":
                confirmed_techniques.append("Single-byte Mutation")

        if mutate_probe[0] == False and "body" in mutate_probe[1]:
            if (http_compare.compare_body(truncate_probe[3].text, arbitrary_probe[3].text) == False) or truncate_probe[
                3
            ].text == "":
                confirmed_techniques.append("Data Truncation")

        if confirmed_techniques:
            context = f"Lightfuzz Cryptographic Probe Submodule detected a parameter ({self.event.data['name']}) to appears to drive a cryptographic operation"
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"Probable Cryptographic Parameter. {self.metadata()} Detection Technique(s): [{', '.join(confirmed_techniques)}]",
                    "context": context,
                }
            )

        # Cryptographic Error String Test
        await self.error_string_search(
            {"truncate value": truncate_probe[3].text, "mutate value": mutate_probe[3].text}, baseline_probe.text
        )

        if confirmed_techniques or (
            "padding" in truncate_probe[3].text.lower() or "padding" in mutate_probe[3].text.lower()
        ):

            # Padding Oracle Test

            if possible_block_cipher:
                self.lightfuzz.debug(
                    "Attempting padding oracle exploit since it looks like a block cipher and we have confirmed crypto"
                )
                await self.padding_oracle(probe_value, cookies)

            # Hash identification / Potential Length extension attack

            data, encoding = CryptoLightfuzz.format_agnostic_decode(probe_value)
            hash_function = self.identify_hash_function(data)
            if hash_function:
                hash_instance = hash_function()
                # if there are any hash functions which match the length, we check the additional parameters to see if they cause identical changes
                # this would indicate they are being used to generate the hash
                if (
                    hash_function
                    and "additional_params" in self.event.data.keys()
                    and self.event.data["additional_params"]
                ):
                    for additional_param_name, additional_param_value in self.event.data["additional_params"].items():
                        try:
                            additional_param_probe = await self.compare_probe(
                                http_compare,
                                self.event.data["type"],
                                probe_value,
                                cookies,
                                additional_params_override={additional_param_name: additional_param_value + "A"},
                            )
                        except HttpCompareError as e:
                            self.lightfuzz.warning(f"Encountered HttpCompareError Sending Compare Probe: {e}")
                            continue
                        # the additional parameter affects the potential hash parameter (suggesting its calculated in the hash)
                        if additional_param_probe[0] == False and (additional_param_probe[1] == mutate_probe[1]):
                            context = f"Lightfuzz Cryptographic Probe Submodule detected a parameter ({self.event.data['name']}) that is a likely a hash, which is connected to another parameter {additional_param_name})"
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"Possible {self.event.data['type']} parameter with {hash_instance.name.upper()} Hash as value. {self.metadata()}, linked to additional parameter [{additional_param_name}]",
                                    "context": context,
                                }
                            )
