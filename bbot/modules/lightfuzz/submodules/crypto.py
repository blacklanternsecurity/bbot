import base64
import hashlib
from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
from urllib.parse import unquote, quote


# Global cache for compiled YARA rules
_compiled_rules_cache = None


class crypto(BaseLightfuzz):
    """
    Detects the use of cryptography in web parameters, and probes for some cryptographic vulnerabilities

    * Cryptographic Error Detection:
       - Detects known cryptographic error messages in server responses.

    * Cryptographic Parameter Value Detection:
       - Detects use of cryptography in web parameter values.
       - Validates by attempting to manipulate the value regardless of its encoding.

    * Length Extension Attack Detection:
       - Identifies parameters which may be expecting hash digests for values, and any linked parameters which invalidate them.

    * Padding Oracle Vulnerabilities:
       - Identifies the presence of cryptographic oracles that could be exploited to arbitrary decrypt or encrypt data for the parameter value.


    """

    friendly_name = "Cryptography Probe"

    # Although we have an envelope system to detect hex and base64 encoded parameter values, those are only assigned when they decode to a valid string.
    # Since crypto values (and serialized objects) will not decode properly, we need a more concise check here to determine how to process them.

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

    # A list of YARA rules for detecting cryptographic error messages
    crypto_error_strings = [
        "invalid mac",
        "padding is invalid",
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

    @property
    def compiled_rules(self):
        """
        We need to cache the compiled YARA rule globally since lightfuzz submodules are recreated for every handle_event
        """
        global _compiled_rules_cache
        if _compiled_rules_cache is None:
            _compiled_rules_cache = self.lightfuzz.helpers.yara.compile_strings(self.crypto_error_strings, nocase=True)
        return _compiled_rules_cache

    @staticmethod
    def format_agnostic_decode(input_string, urldecode=False):
        """
        Decodes a string from either hex or base64 (without knowing which first), and optionally URL-decoding it first.

        Parameters:
        - input_string (str): The string to decode.
        - urldecode (bool): If True, URL-decodes the input first.

        Returns:
        - tuple: (decoded data, encoding type: 'hex', 'base64', or 'unknown').
        """
        encoding = "unknown"
        if urldecode:
            input_string = unquote(input_string)
        if BaseLightfuzz.is_hex(input_string):
            data = bytes.fromhex(input_string)
            encoding = "hex"
        elif BaseLightfuzz.is_base64(input_string):
            data = base64.b64decode(input_string)
            encoding = "base64"
        else:
            data = str
        return data, encoding

    @staticmethod
    def format_agnostic_encode(data, encoding, urlencode=False):
        """
        Encodes data into hex or base64, with optional URL-encoding.

        Parameters:
        - data (bytes): The data to encode.
        - encoding (str): The encoding type ('hex' or 'base64').
        - urlencode (bool): If True, URL-encodes the result.

        Returns:
        - str: The encoded data as a string.

        Raises:
        - ValueError: If an unsupported encoding type is specified.
        """
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
        """
        Modifies a cryptographic string by either truncating it, mutating a byte at a specified position, or extending it with null bytes.

        Parameters:
        - input_string (str): The string to modify.
        - action (str): The action to perform ('truncate', 'mutate', 'extend').
        - position (int): The position to mutate (only used if action is 'mutate').
        - extension_length (int): The number of null bytes to add if action is 'extend'.

        Returns:
        - str: The modified string.
        """
        if not isinstance(input_string, str):
            input_string = str(input_string)

        data, encoding = crypto.format_agnostic_decode(input_string)
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
        return crypto.format_agnostic_encode(modified_data, encoding)

    # Check if the entropy of the data is greater than the threshold, indicating it is likely encrypted
    def is_likely_encrypted(self, data, threshold=4.5):
        entropy = self.lightfuzz.helpers.calculate_entropy(data)
        return entropy >= threshold

    # Perform basic cryptanalysis on the input string, attempting to determine if it is likely encrypted and if it is a block cipher
    def cryptanalysis(self, input_string):
        likely_crypto = False
        possible_block_cipher = False
        data, encoding = self.format_agnostic_decode(input_string)
        likely_crypto = self.is_likely_encrypted(data)
        data_length = len(data)
        if data_length % 8 == 0:
            possible_block_cipher = True
        return likely_crypto, possible_block_cipher

    # Determine possible block sizes for a given ciphertext length
    @staticmethod
    def possible_block_sizes(ciphertext_length):
        potential_block_sizes = [8, 16]
        possible_sizes = []
        for block_size in potential_block_sizes:
            num_blocks = ciphertext_length // block_size
            if ciphertext_length % block_size == 0 and num_blocks >= 2:
                possible_sizes.append(block_size)
        return possible_sizes

    async def padding_oracle_execute(self, original_data, encoding, block_size, cookies, possible_first_byte=True):
        """
        Execute the padding oracle attack for a given block size.
        The goal here is not actual exploitation (arbitrary encryption or decryption), but rather to definitively confirm whether padding oracle vulnerability exists and is exploitable.

        Parameters:
        - original_data (bytes): The original ciphertext data.
        - encoding (str): The encoding type ('hex' or 'base64').
        - block_size (int): The block size to use for the padding oracle attack.
        - cookies (dict): Cookies to include, if any
        - possible_first_byte (bool): If True, use the first byte as the baseline byte.

        Returns:
        - bool: True if the padding oracle attack is successful.
        """
        ivblock = b"\x00" * block_size  # initialize the IV block with null bytes
        paddingblock = b"\x00" * block_size  # initialize the padding block with null bytes
        datablock = original_data[-block_size:]  # extract the last block of the original data

        # This handling the 1/255 chance that the first byte is correct padding which would cause a false negative.
        if possible_first_byte:
            baseline_byte = b"\xff"  # set the baseline byte to 0xff
            starting_pos = 0  # set the starting position to 0
        else:
            baseline_byte = b"\x00"  # set the baseline byte to 0x00
            starting_pos = 1  # set the starting position to 1
        # first obtain
        baseline = self.compare_baseline(
            self.event.data["type"],
            self.format_agnostic_encode(ivblock + paddingblock[:-1] + baseline_byte + datablock, encoding),
            cookies,
        )
        differ_count = 0
        # for each possible byte value, send a probe and check if the response is different
        for i in range(starting_pos, starting_pos + 254):
            byte = bytes([i])
            oracle_probe = await self.compare_probe(
                baseline,
                self.event.data["type"],
                self.format_agnostic_encode(ivblock + paddingblock[:-1] + byte + datablock, encoding),
                cookies,
            )
            # oracle_probe[0] will be false if the response is different - oracle_probe[1] stores what aspect of the response is different (headers, body, code)
            if oracle_probe[0] is False and "body" in oracle_probe[1]:
                differ_count += 1

                if i == 2:
                    if possible_first_byte is True:
                        # Thats two results which appear "different". Since this is the first run, it's entirely possible \x00 was the correct padding.
                        # We will break from this loop and redo it with the last byte as the baseline instead of the first
                        return None
                    else:
                        # Now that we have tried the run twice, we know it can't be because the first byte was the correct padding, and we know it is not vulnerable
                        return False
        # A padding oracle vulnerability will produce exactly one different response, and no more, so this is likely a real padding oracle
        if differ_count == 1:
            return True
        return False

    async def padding_oracle(self, probe_value, cookies):
        data, encoding = self.format_agnostic_decode(probe_value)
        possible_block_sizes = self.possible_block_sizes(
            len(data)
        )  # determine possible block sizes for the ciphertext

        for block_size in possible_block_sizes:
            padding_oracle_result = await self.padding_oracle_execute(data, encoding, block_size, cookies)
            # if we get a negative result first, theres a 1/255 change it's a false negative. To rule that out, we must retry again with possible_first_byte set to false
            if padding_oracle_result is None:
                self.debug("still could be in a possible_first_byte situation - retrying with different first byte")
                padding_oracle_result = await self.padding_oracle_execute(
                    data, encoding, block_size, cookies, possible_first_byte=False
                )

            if padding_oracle_result is True:
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
        """
        Search for cryptographic error strings using YARA rules in the provided text dictionary and baseline text.
        """
        matching_techniques = set()
        matching_strings = set()

        # Check each manipulation technique
        for label, text in text_dict.items():
            matches = await self.lightfuzz.helpers.yara.match(self.compiled_rules, text)
            if matches:
                matching_techniques.add(label)
                for matched_string in matches:
                    matching_strings.add(matched_string)

        # Check for false positives by scanning baseline text
        context = f"Lightfuzz Cryptographic Probe Submodule detected a cryptographic error after manipulating parameter: [{self.event.data['name']}]"
        if matching_strings:
            baseline_matches = await self.lightfuzz.helpers.yara.match(self.compiled_rules, baseline_text)
            baseline_strings = set()
            for matched_string in baseline_matches:
                baseline_strings.add(matched_string)

            # Only report strings that weren't in the baseline
            unique_matches = matching_strings - baseline_strings
            if unique_matches:
                self.results.append(
                    {
                        "type": "FINDING",
                        "description": f"Possible Cryptographic Error. {self.metadata()} Strings: [{','.join(unique_matches)}] Detection Technique(s): [{','.join(matching_techniques)}]",
                        "context": context,
                    }
                )

            else:
                self.debug(
                    f"Aborting cryptographic error reporting - baseline_text already contained detected string(s) ({','.join(baseline_strings)})"
                )

    # Identify the hash function based on the length of the hash
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
        probe_value = self.incoming_probe_value(populate_empty=False)

        if not probe_value:
            self.debug(
                f"The Cryptography Probe Submodule requires original value, aborting [{self.event.data['type']}] [{self.event.data['name']}]"
            )
            return

        # obtain the baseline probe to compare against
        baseline_probe = await self.baseline_probe(cookies)
        if not baseline_probe:
            self.verbose(f"Couldn't get baseline_probe for url {self.event.data['url']}, aborting")
            return

        # perform the manipulation techniques
        try:
            truncate_probe_value = self.modify_string(probe_value, action="truncate")
            mutate_probe_value = self.modify_string(probe_value, action="mutate")
        except ValueError as e:
            self.debug(f"Encountered error modifying value for parameter [{self.event.data['name']}]: {e} , aborting")
            return

        # Basic crypanalysis
        likely_crypto, possible_block_cipher = self.cryptanalysis(probe_value)

        # if the value is not likely to be cryptographic, we can skip the rest of the tests
        if not likely_crypto:
            self.debug("Parameter value does not appear to be cryptographic, aborting tests")
            return

        # Cryptographic Response Divergence Test

        http_compare = self.compare_baseline(self.event.data["type"], probe_value, cookies)
        try:
            arbitrary_probe = await self.compare_probe(http_compare, self.event.data["type"], "AAAAAAA", cookies)  #
            truncate_probe = await self.compare_probe(
                http_compare, self.event.data["type"], truncate_probe_value, cookies
            )  # manipulate the value by truncating a byte
            mutate_probe = await self.compare_probe(
                http_compare, self.event.data["type"], mutate_probe_value, cookies
            )  # manipulate the value by mutating a byte in place
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")
            return

        confirmed_techniques = []
        # mutate_probe[0] will be false if the response is different - mutate_probe[1] stores what aspect of the response is different (headers, body, code)
        # ensure the difference is in the body and not the headers or code
        # if the body is different and not empty, we have confirmed that single-byte mutation affected the response body
        if mutate_probe[0] is False and "body" in mutate_probe[1]:
            if (http_compare.compare_body(mutate_probe[3].text, arbitrary_probe[3].text) is False) or mutate_probe[
                3
            ].text == "":
                confirmed_techniques.append("Single-byte Mutation")

        # if the body is different and not empty, we have confirmed that byte truncation affected the response body
        if truncate_probe[0] is False and "body" in truncate_probe[1]:
            if (http_compare.compare_body(truncate_probe[3].text, arbitrary_probe[3].text) is False) or truncate_probe[
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
        # Check if cryptographic error strings are present in the response after performing the manipulation techniques
        await self.error_string_search(
            {"truncate value": truncate_probe[3].text, "mutate value": mutate_probe[3].text}, baseline_probe.text
        )
        # if we have any confirmed techniques, or the word "padding" is in the response, we need to check for a padding oracle
        if confirmed_techniques or (
            "padding" in truncate_probe[3].text.lower() or "padding" in mutate_probe[3].text.lower()
        ):
            # Padding Oracle Test
            if possible_block_cipher:
                self.debug(
                    "Attempting padding oracle exploit since it looks like a block cipher and we have confirmed crypto"
                )
                await self.padding_oracle(probe_value, cookies)

            # Hash identification / Potential Length extension attack
            data, encoding = crypto.format_agnostic_decode(probe_value)
            # see if its possible that a given value is a hash, and if so, which one
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
                    # for each additional parameter, we send a probe and check if it causes the same change in the response as the original probe
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
                            self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")
                            continue
                        # the additional parameter affects the potential hash parameter (suggesting its calculated in the hash)
                        # This is a potential length extension attack
                        if additional_param_probe[0] is False and (additional_param_probe[1] == mutate_probe[1]):
                            context = f"Lightfuzz Cryptographic Probe Submodule detected a parameter ({self.event.data['name']}) that is a likely a hash, which is connected to another parameter {additional_param_name})"
                            self.results.append(
                                {
                                    "type": "FINDING",
                                    "description": f"Possible {self.event.data['type']} parameter with {hash_instance.name.upper()} Hash as value. {self.metadata()}, linked to additional parameter [{additional_param_name}]",
                                    "context": context,
                                }
                            )
