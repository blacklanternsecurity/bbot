import base64
import hashlib
from .base import BaseLightfuzz
from bbot.errors import HttpCompareError
from urllib.parse import unquote, quote


# Global cache for compiled YARA rules
_compiled_rules_cache = None


def _xor_bytes(a, b):
    """XOR two bytestrings truncated to the shorter length."""
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def _leading_zero_run(b):
    """Number of leading 0x00 bytes in b."""
    n = 0
    for byte in b:
        if byte == 0:
            n += 1
        else:
            break
    return n


def _ascii_xor_score(b):
    """Fraction of bytes <= 0x60.

    XOR of two printable-ASCII strings overwhelmingly lands in [0x00, 0x60]
    (letters XOR letters yield 0x00-0x3F, digits XOR digits 0x00-0x3F, etc.).
    Truly random bytes land in this range only ~38% of the time. A high score
    is the classic "many-time-pad smell."
    """
    if not b:
        return 0.0
    return sum(1 for x in b if x <= 0x60) / len(b)


def _is_structured_id_pair(bytes_a, bytes_b, xored, zero_run):
    """True when the pair looks like structured identifiers (MongoDB ObjectIds,
    hex timestamps, sequential counters, time-ordered UUIDs) rather than
    reused-keystream ciphertexts.

    Structured IDs share a long byte prefix (timestamp, process ID, ...) and
    differ only in a short counter/random suffix.  Their XOR has a long leading-
    zero run followed by a sparse or random tail -- superficially identical to
    keystream reuse with shared-prefix plaintexts, but distinguishable by what
    the tail looks like.

    Real many-time-pad: the tail is XOR of diverging ASCII plaintexts -- dense,
    diverse bytes mostly in [0x00, 0x60].

    Structured IDs: the tail is either a small counter delta (sparse zeros with
    one nonzero byte) or random machine/process bytes (fails ASCII-XOR check).
    """
    tail = xored[zero_run:]

    # 0-1 differing bytes is always a counter tick.
    if len(tail) < 2:
        return True

    # Same-length values whose entire difference fits in <= 4 bytes are
    # incrementing identifiers (MongoDB ObjectId 3-byte counter, hex
    # timestamps differing by 1-2 bytes, etc.).
    if len(bytes_a) == len(bytes_b) and len(tail) <= 4:
        return True

    # For longer tails: real many-time-pad XOR reveals XOR of diverging ASCII
    # plaintexts -- dense nonzero bytes mostly in [0x00, 0x60].  Random
    # suffixes (UUID v7 random bits, different-process machine bytes) and
    # sparse counters both fail these checks.
    distinct_nonzero = len(set(b for b in tail if b != 0))
    if distinct_nonzero < 2:
        return True

    if _ascii_xor_score(tail) < 0.7:
        return True

    return False


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

    * ECB Mode Detection:
       - Passively detects ECB mode encryption by checking for repeated ciphertext blocks in parameter values (zero HTTP requests).

    * CBC Bit-Flipping Detection:
       - Actively tests whether mutating different byte positions in the penultimate ciphertext block produces distinguishable server responses,
         indicating CBC mode without integrity protection (2 HTTP requests).

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
    def is_plausible_base64_crypto(s):
        """
        Check if a string is plausibly base64-encoded cryptographic data.
        Non-standard encodings like F5 BIG-IP's A-P nibble encoding use a narrow
        consecutive character range that technically round-trips as base64 but is
        not actual base64. Real base64 of encrypted/random bytes spans a wide
        character range (typically 70+).
        """
        unique_chars = set(s) - set("=")
        if len(s) >= 16 and unique_chars:
            char_ords = [ord(c) for c in unique_chars]
            if max(char_ords) - min(char_ords) <= 20:
                return False
        return True

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
        elif BaseLightfuzz.is_base64(input_string) and crypto.is_plausible_base64_crypto(input_string):
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
            if position is None:
                position = len(data) // 2
            if position < 0 or position >= len(data):
                raise ValueError("Position out of range")
            byte_list = list(data)
            byte_list[position] = (byte_list[position] + 1) % 256
            modified_data = bytes(byte_list)
        elif action == "extend":
            modified_data = data + (b"\x00" * extension_length)
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

    def _collect_keystream_candidates(self, probe_value):
        """Return [(label, raw, bytes)] for every hex-shaped candidate worth pairwise-XORing.

        Sources, in order:
          1. The current parameter's value (probe_value).
          2. Every value in ``event.data["additional_params"]`` (siblings on the same form/URL).
          3. Every value in ``event.data["same_param_values"]`` (other observed values for the
             same param name seen on the same HTTP_RESPONSE, e.g. a results page with many
             ``<a href="?SortBy=<hex>">`` links — populated by excavate's parameter extractor).
        """
        param_name = self.event.data.get("name", "")
        sources = [(param_name, probe_value)]
        additional_params = self.event.data.get("additional_params") or {}
        for k, v in additional_params.items():
            sources.append((k, v))
        for v in self.event.data.get("same_param_values") or []:
            sources.append((param_name, v))

        seen_bytes = set()
        candidates = []
        for label, value in sources:
            if not value or not isinstance(value, str):
                continue
            decoded, encoding = self.format_agnostic_decode(value)
            # Hex only: base64's alphabet overlaps heavily with URL-path / identifier
            # characters, so plaintext URL paths sharing a prefix round-trip as base64
            # and XOR to a leading-zero run, producing a false-positive keystream-reuse
            # finding. Hex's [0-9a-f] alphabet has no such overlap with structured
            # plaintext, so restricting to hex eliminates that class of FP.
            if encoding != "hex":
                continue
            # Digit-only strings (e.g. "7276383284") are valid hex but are almost
            # certainly plain decimal IDs (account numbers, zip codes, etc.). Their
            # hex-decoded bytes XOR to small values that trivially pass the ascii_score
            # threshold, producing false keystream-reuse findings.
            if value.isdigit():
                continue
            if len(decoded) < 3:
                continue
            if decoded in seen_bytes:
                continue
            seen_bytes.add(decoded)
            candidates.append((label, value, decoded))
            if len(candidates) >= 50:
                break
        return candidates

    def detect_keystream_reuse(self, probe_value):
        """Detect "many-time-pad" / keystream-reuse weakness across multiple ciphertexts.

        When the same keystream is reused across encryptions (e.g. ColdFusion's legacy
        CFMX_COMPAT, hand-rolled XOR ciphers with no IV), XOR-ing any two ciphertexts
        yields the XOR of their plaintexts. If the plaintexts share a prefix, the XOR
        result starts with zero bytes; for natural-language / identifier plaintexts the
        result lands almost entirely in [0x00, 0x60] (the "many-time-pad smell").

        Runs before the entropy gate because the very plaintexts this catches (short
        ASCII identifiers like ``skillcd``) often produce ciphertext below the 4.5-bit
        entropy threshold the gate uses.
        """
        candidates = self._collect_keystream_candidates(probe_value)
        if len(candidates) < 2:
            return

        best = None
        for i in range(len(candidates)):
            for j in range(i + 1, len(candidates)):
                label_a, raw_a, bytes_a = candidates[i]
                label_b, raw_b, bytes_b = candidates[j]
                xored = _xor_bytes(bytes_a, bytes_b)
                if len(xored) < 3:
                    continue
                zero_run = _leading_zero_run(xored)
                ascii_score = _ascii_xor_score(xored)
                # At least 2 leading zero bytes OR ≥90% of bytes in ASCII-XOR-ASCII range
                if zero_run < 2 and ascii_score < 0.9:
                    continue
                # A leading-zero run alone is the hallmark of structured hex
                # identifiers (MongoDB ObjectIds, hex timestamps, sequential
                # counters, time-ordered UUIDs) sharing a byte prefix -- not
                # keystream reuse.  Filter those out by examining the tail.
                if zero_run >= 2 and _is_structured_id_pair(bytes_a, bytes_b, xored, zero_run):
                    continue
                pair_score = (zero_run, ascii_score)
                if best is None or pair_score > (best[0], best[1]):
                    best = (zero_run, ascii_score, label_a, raw_a, label_b, raw_b, xored)

        if best is None:
            return

        zero_run, ascii_score, label_a, raw_a, label_b, raw_b, xored = best
        if zero_run >= 5:
            severity, confidence = "HIGH", "CONFIRMED"
        elif zero_run >= 3 or ascii_score >= 0.95:
            severity, confidence = "HIGH", "HIGH"
        else:
            severity, confidence = "MEDIUM", "MEDIUM"

        description = (
            "Stream Cipher Keystream Reuse (Many-Time-Pad). "
            f"Two parameter values XOR to a {zero_run}-byte leading-zero run: "
            f"[{label_a}]={raw_a} XOR [{label_b}]={raw_b} = {xored.hex()}. "
            f"{self.metadata()}"
        )
        context = (
            "Lightfuzz Cryptographic Probe Submodule detected stream-cipher "
            f"keystream reuse across parameters [{label_a}] and [{label_b}]"
        )
        self.results.append(
            {
                "name": "Stream Cipher Keystream Reuse",
                "severity": severity,
                "confidence": confidence,
                "description": description,
                "context": context,
            }
        )

    def detect_ecb(self, probe_value):
        """
        Passively detect ECB mode encryption by checking for repeated ciphertext blocks.
        ECB encrypts each block independently, so identical plaintext blocks produce identical
        ciphertext blocks. Zero HTTP requests required.
        """
        data, encoding = self.format_agnostic_decode(probe_value)
        if encoding == "unknown":
            return
        for block_size in self.possible_block_sizes(len(data)):
            blocks = [data[i : i + block_size] for i in range(0, len(data), block_size)]
            if len(blocks) != len(set(blocks)):
                context = f"Lightfuzz Cryptographic Probe Submodule detected ECB mode encryption in parameter: [{self.event.data['name']}]"
                self.results.append(
                    {
                        "severity": "MEDIUM",
                        "name": "ECB Mode Encryption Detected",
                        "confidence": "MEDIUM",
                        "description": f"ECB Mode Encryption Detected. Block size: [{block_size}] {self.metadata()}",
                        "context": context,
                    }
                )
                return  # Report first matching block size only

    async def cbc_bitflip(self, probe_value, cookies):
        """
        Detect CBC bit-flipping vulnerability by mutating different byte positions in the
        penultimate ciphertext block. In CBC mode, modifying byte N of block K affects byte N
        of the decrypted block K+1. If the server produces distinguishable responses for
        different mutation positions, it indicates CBC without integrity protection.
        Cost: 2 HTTP requests.
        """
        data, encoding = self.format_agnostic_decode(probe_value)
        if encoding == "unknown":
            return
        # Stability pre-check: verify the endpoint returns consistent responses
        if not await self._check_endpoint_stability(probe_value, encoding, cookies):
            return
        for block_size in self.possible_block_sizes(len(data)):
            num_blocks = len(data) // block_size
            if num_blocks < 2:
                continue
            penultimate_start = (num_blocks - 2) * block_size
            # Mutate first byte of penultimate block
            try:
                probe_a = self.modify_string(probe_value, action="mutate", position=penultimate_start)
            except ValueError:
                continue
            # Mutate middle byte of penultimate block
            try:
                probe_b = self.modify_string(
                    probe_value, action="mutate", position=penultimate_start + block_size // 2
                )
            except ValueError:
                continue
            # Use probe_a as the baseline, compare probe_b against it
            http_compare = self.compare_baseline(self.event.data["type"], probe_a, cookies)
            try:
                result = await self.compare_probe(http_compare, self.event.data["type"], probe_b, cookies)
            except HttpCompareError as e:
                self.verbose(f"Encountered HttpCompareError during CBC bit-flip test: {e}")
                continue
            if result[0] is False and "body" in result[1]:
                # Strip reflected probe values to avoid false positives
                stripped_baseline = http_compare.baseline.text
                stripped_probe = result[3].text
                for encoded_a, encoded_b in [
                    (probe_a, probe_b),
                    (probe_a.replace("+", " "), probe_b.replace("+", " ")),
                    (quote(probe_a), quote(probe_b)),
                ]:
                    stripped_baseline = stripped_baseline.replace(encoded_a, "")
                    stripped_probe = stripped_probe.replace(encoded_b, "")
                if stripped_baseline == stripped_probe:
                    continue
                context = f"Lightfuzz Cryptographic Probe Submodule detected probable CBC bit-flipping in parameter: [{self.event.data['name']}]"
                self.results.append(
                    {
                        "severity": "MEDIUM",
                        "name": "CBC Bit-Flipping Detected",
                        "confidence": "MEDIUM",
                        "description": f"CBC Bit-Flipping Detected. Block size: [{block_size}] {self.metadata()}",
                        "context": context,
                    }
                )
                return  # Report first matching block size only

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

        baseline_probe_value = self.format_agnostic_encode(
            ivblock + paddingblock[:-1] + baseline_byte + datablock, encoding
        )
        baseline = self.compare_baseline(
            self.event.data["type"],
            baseline_probe_value,
            cookies,
        )
        differ_count = 0
        # for each possible byte value, send a probe and check if the response is different
        for i in range(starting_pos, starting_pos + 254):
            byte = bytes([i])
            probe_value = self.format_agnostic_encode(ivblock + paddingblock[:-1] + byte + datablock, encoding)
            try:
                oracle_probe = await self.compare_probe(
                    baseline,
                    self.event.data["type"],
                    probe_value,
                    cookies,
                )
            except HttpCompareError as e:
                self.verbose(f"Encountered HttpCompareError during padding oracle probe: {e}")
                return False
            # oracle_probe[0] will be false if the response is different - oracle_probe[1] stores what aspect of the response is different (headers, body, code)
            if oracle_probe[0] is False and "body" in oracle_probe[1]:
                # When the server reflects submitted values or reveals decrypted data, every probe will differ in the body. Strip the known probe values from both responses and re-compare.
                stripped_baseline = baseline.baseline.text
                stripped_probe = oracle_probe[3].text
                for encoded_baseline, encoded_probe in [
                    (baseline_probe_value, probe_value),
                    (baseline_probe_value.replace("+", " "), probe_value.replace("+", " ")),
                    (quote(baseline_probe_value), quote(probe_value)),
                ]:
                    stripped_baseline = stripped_baseline.replace(encoded_baseline, "")
                    stripped_probe = stripped_probe.replace(encoded_probe, "")
                if stripped_baseline == stripped_probe:
                    continue
                # If the server reveals decrypted data, the response may differ by only a few bytes (the varying decrypted byte). Tolerate small character-level differences.
                if len(stripped_baseline) == len(stripped_probe):
                    char_diffs = sum(1 for a, b in zip(stripped_baseline, stripped_probe) if a != b)
                    if char_diffs <= 5:
                        continue
                differ_count += 1
        self.debug(f"padding_oracle_execute: finished loop. differ_count={differ_count}")
        # A padding oracle vulnerability can produce a small number of different responses.
        # The correct \x01 padding byte always differs, but also, multi-byte padding values (\x02\x02, \x03\x03\x03, etc.) can also produce valid padding if the intermediate state randomly aligns. At most 'block_size' of such values are possible.
        if 1 <= differ_count <= block_size:
            return True
        # If too many probes differ, the baseline byte may have been the correct padding byte (1/255 chance).
        # In that case, the baseline response represents "valid padding" and nearly all probes appear different.
        # Retry with a different baseline byte to rule this out.
        if possible_first_byte and differ_count > block_size:
            return None
        return False

    async def _check_endpoint_stability(self, probe_value, encoding, cookies):
        """Send the same probe value multiple times and verify the endpoint returns consistent responses.
        Returns True if stable, False if responses vary for identical inputs (jitter)."""
        data, _ = self.format_agnostic_decode(probe_value)
        if encoding == "unknown":
            return True
        # Build a fixed probe to test stability
        stability_value = self.format_agnostic_encode(b"\x00" * 16 + data[-16:], encoding)
        stability_hashes = []
        for _ in range(3):
            r = await self.standard_probe(self.event.data["type"], cookies, stability_value)
            if r:
                body = r.text
                for encoded in [stability_value, stability_value.replace("+", " "), quote(stability_value)]:
                    body = body.replace(encoded, "")
                stability_hashes.append(hash(body))
        if len(set(stability_hashes)) > 1:
            self.debug(
                f"Endpoint produces unstable responses for identical inputs "
                f"({len(set(stability_hashes))}/{len(stability_hashes)} unique), "
                f"skipping differential analysis"
            )
            return False
        return True

    async def padding_oracle(self, probe_value, cookies):
        data, encoding = self.format_agnostic_decode(probe_value)
        possible_block_sizes = self.possible_block_sizes(
            len(data)
        )  # determine possible block sizes for the ciphertext

        # Stability pre-check: verify the endpoint returns consistent responses
        # for identical inputs before attempting differential analysis
        if not await self._check_endpoint_stability(probe_value, encoding, cookies):
            return

        for block_size in possible_block_sizes:
            padding_oracle_result = await self.padding_oracle_execute(data, encoding, block_size, cookies)
            # if we get a negative result first, theres a 1/255 change it's a false negative. To rule that out, we must retry again with possible_first_byte set to false
            if padding_oracle_result is None:
                self.debug("still could be in a possible_first_byte situation - retrying with different first byte")
                padding_oracle_result = await self.padding_oracle_execute(
                    data, encoding, block_size, cookies, possible_first_byte=False
                )

            if padding_oracle_result is True:
                # Confirmation round: re-run to rule out jitter-based false positives
                self.debug(f"Initial padding oracle detection for block_size={block_size}, running confirmation round")
                confirmation_result = await self.padding_oracle_execute(data, encoding, block_size, cookies)
                if confirmation_result is None:
                    confirmation_result = await self.padding_oracle_execute(
                        data, encoding, block_size, cookies, possible_first_byte=False
                    )
                if confirmation_result is not True:
                    self.debug(
                        f"Confirmation round failed for block_size={block_size} - likely jitter false positive, suppressing"
                    )
                    continue

                context = f"Lightfuzz Cryptographic Probe Submodule detected a probable padding oracle vulnerability after manipulating parameter: [{self.event.data['name']}]"
                self.results.append(
                    {
                        "severity": "HIGH",
                        "name": "Padding Oracle Vulnerability",
                        "confidence": "HIGH",
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
                        "name": "Possible Cryptographic Error",
                        "severity": "INFO",
                        "confidence": "LOW",
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
            28: hashlib.sha224,
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

        # Cross-value: detect keystream-reuse / many-time-pad. Runs before the entropy gate
        # because the short ASCII identifier plaintexts this catches often produce ciphertext
        # below the 4.5-bit threshold the gate uses. Zero HTTP requests.
        self.detect_keystream_reuse(probe_value)

        # obtain the baseline probe to compare against
        baseline_probe = await self.baseline_probe(cookies)
        if not baseline_probe:
            self.verbose(f"Couldn't get baseline_probe for url {self.event.url}, aborting")
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

        # ECB Mode Detection (passive, zero HTTP requests)
        if possible_block_cipher:
            self.detect_ecb(probe_value)

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

        # If any probe got no response (e.g. WAF-blocked), we can't reason about diffs; abort.
        if arbitrary_probe[3] is None or truncate_probe[3] is None or mutate_probe[3] is None:
            self.verbose(f"One or more compare probes returned no response for url {self.event.url}, aborting")
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
                    "name": "Probable Cryptographic Parameter",
                    "severity": "INFO",
                    "confidence": "LOW",
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

                # CBC Bit-Flipping Test
                await self.cbc_bitflip(probe_value, cookies)

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
                        if additional_param_value is None:
                            continue
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
                                    "name": "Possible Length Extension Attack",
                                    "severity": "INFO",
                                    "confidence": "LOW",
                                    "description": f"Possible {self.event.data['type']} parameter with {hash_instance.name.upper()} Hash as value. {self.metadata()}, linked to additional parameter [{additional_param_name}]",
                                    "context": context,
                                }
                            )
