import re
from .base import ModuleTestBase


class TestTelerik(ModuleTestBase):
    targets = ["http://127.0.0.1:8888", "http://127.0.0.1:8888/telerik.aspx"]
    modules_overrides = ["http", "telerik"]
    config_overrides = {"modules": {"telerik": {"exploit_rau": True}}}

    async def setup_before_prep(self, module_test):
        # Simulate Telerik.Web.UI.WebResource.axd?type=rau detection
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"}
        respond_args = {
            "response_data": '{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate a vulnerable RAU endpoint: any POST returns the fileInfo blob.
        expect_args = {
            "method": "POST",
            "uri": "/Telerik.Web.UI.WebResource.axd",
            "query_string": "type=rau",
        }
        respond_args = {
            "response_data": '{"fileInfo":{"FileName":"RAU_crypto.bypass","ContentType":"text/html","ContentLength":5,"DateJson":"2019-01-02T03:04:05.067Z","Index":0}, "metaData":"stub"}'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate SpellCheckHandler detection
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"}
        respond_args = {"status": 500}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate SpellCheckHandler false positive detection
        expect_args = {"method": "GET", "uri": "/AAAAAAAAAAAAAA.axd"}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate ChartImage.axd Detection
        expect_args = {
            "method": "GET",
            "uri": "/ChartImage.axd",
            "query_string": "ImageName=bqYXJAqm315eEd6b%2bY4%2bGqZpe7a1kY0e89gfXli%2bjFw%3d",
        }
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/ChartImage.axd", "query_string": "ImageName="}
        respond_args = {"status": 500}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate Dialog Parameters in URL
        expect_args = {"method": "GET", "uri": "/telerik.aspx"}
        respond_args = {"response_data": '{"ImageManager":{"SerializedParameters":"MBwZB"}'}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback
        expect_args = {"uri": re.compile(r"^/\w{10}$")}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.scan.modules["telerik"].telerik_versions = ["2014.2.724", "2014.3.1024", "2015.1.204"]
        module_test.scan.modules["telerik"].dialoghandler_urls = [
            "Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx",
            "App_Master/Telerik.Web.UI.DialogHandler.aspx",
            "AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        telerik_axd_detection = False
        telerik_axd_vulnerable = False
        telerik_spellcheck_detection = False
        telerik_dialoghandler_detection = False
        telerik_chartimage_detection = False
        telerik_http_response_parameters_detection = False

        for e in events:
            if e.type == "FINDING" and e.data.get("name") == "Telerik RAU Handler":
                telerik_axd_detection = True
                continue

            if e.type == "FINDING" and e.data.get("name") == "Telerik RAU RCE (CVE-2017-11317)":
                telerik_axd_vulnerable = True
                continue

            if e.type == "FINDING" and e.data.get("name") == "Telerik DialogHandler":
                if "SerializedParameters" in e.data.get("description", ""):
                    telerik_http_response_parameters_detection = True
                else:
                    telerik_dialoghandler_detection = True
                continue

            if e.type == "FINDING" and e.data.get("name") == "Telerik SpellCheckHandler":
                telerik_spellcheck_detection = True
                continue

            if e.type == "FINDING" and e.data.get("name") == "Telerik ChartImage Handler":
                telerik_chartimage_detection = True
                continue

        assert telerik_axd_detection, "Telerik AXD detection failed"
        assert telerik_axd_vulnerable, "Telerik vulnerable AXD detection failed"
        assert telerik_spellcheck_detection, "Telerik spellcheck detection failed"
        assert telerik_dialoghandler_detection, "Telerik dialoghandler detection failed"
        assert telerik_chartimage_detection, "Telerik chartimage detection failed"
        assert telerik_http_response_parameters_detection, "Telerik SerializedParameters detection failed"


class TestTelerikRAUDefaultKeys(ModuleTestBase):
    """
    RAU default-keys probe (safe, no upload): fake-version payload triggers
    'Could not load file or assembly' when default keys are still accepted.
    """

    targets = ["http://127.0.0.1:8888"]
    module_name = "telerik"
    modules_overrides = ["http", "telerik"]
    config_overrides = {
        "modules": {
            "telerik": {
                "exploit_rau": False,
                "try_known_keys": False,
                "probe_dialoghandler_oracle": False,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"},
            respond_args={
                "response_data": '{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }'
            },
        )
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"},
            respond_args={
                "response_data": (
                    "Exception Details: System.IO.FileLoadException: Could not load file or assembly "
                    "'Telerik.Web.UI, Version=9999.9.999, Culture=neutral, PublicKeyToken=121fae78165ba3d4'"
                )
            },
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"},
            respond_args={"status": 404},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/ChartImage.axd"},
            respond_args={"status": 404},
        )

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].dialoghandler_urls = []

    def check(self, module_test, events):
        handler_detected = any(e.type == "FINDING" and e.data.get("name") == "Telerik RAU Handler" for e in events)
        keys_accepted = any(
            e.type == "FINDING" and e.data.get("name") == "Telerik RAU Default Keys Accepted (CVE-2017-11317)"
            for e in events
        )
        rce_confirmed = any(
            e.type == "FINDING" and e.data.get("name") == "Telerik RAU RCE (CVE-2017-11317)" for e in events
        )
        assert handler_detected, "Expected Telerik RAU Handler INFO finding"
        assert keys_accepted, "Expected Telerik RAU Default Keys Accepted HIGH finding"
        assert not rce_confirmed, "Should NOT emit RCE finding without exploit_rau=True"


class TestTelerikDialogHandlerOracle(ModuleTestBase):
    """CVE-2017-9248 quick_check: PBKDF1_MS 'Length cannot be less than zero' oracle → HIGH finding."""

    targets = ["http://127.0.0.1:8888"]
    module_name = "telerik"
    modules_overrides = ["http", "telerik"]
    config_overrides = {
        "modules": {
            "telerik": {
                "probe_dialoghandler_oracle": True,
                "try_known_keys": False,
                "exploit_rau": False,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        # RAU handler: not present
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"},
            respond_args={"status": 404},
        )
        # DialogHandler discovery: default path hits with the deserialize-error banner
        module_test.set_expect_requests(
            expect_args={
                "method": "GET",
                "uri": "/Telerik.Web.UI.DialogHandler.aspx",
                "query_string": "dp=1",
            },
            respond_args={
                "response_data": "<div>Cannot deserialize dialog parameters. Please refresh the editor page.</div>",
            },
        )
        # KDF-mode probe (POST dialogParametersHolder=AAAA) returns pre-patch PBKDF1_MS banner
        # so the oracle-probe gate lets us proceed past known-key skip (try_known_keys=False)
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/Telerik.Web.UI.DialogHandler.aspx"},
            respond_args={"response_data": "Server Error: Length cannot be less than zero. Parameter name: length."},
        )
        # find_baseline probe: GET ?dp=<base64(4 test bytes)> should leak an oracle error string
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.DialogHandler.aspx"},
            respond_args={"response_data": "Server Error: Index was outside the bounds of the array."},
        )
        # SpellCheck/ChartImage: not present
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"},
            respond_args={"status": 404},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/ChartImage.axd"},
            respond_args={"status": 404},
        )

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].dialoghandler_urls = [
            "Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        oracle_found = any(
            e.type == "FINDING" and e.data.get("name") == "Telerik DialogHandler Oracle (CVE-2017-9248)"
            for e in events
        )
        assert oracle_found, "Expected Telerik DialogHandler Oracle finding (CVE-2017-9248)"


class TestTelerikDialogHandlerKnownKey(ModuleTestBase):
    """PBKDF1_MS mode: hash key + enc key each solvable via distinct oracle strings → CRITICAL finding."""

    targets = ["http://127.0.0.1:8888"]
    module_name = "telerik"
    modules_overrides = ["http", "telerik"]
    config_overrides = {
        "modules": {
            "telerik": {
                "probe_dialoghandler_oracle": False,
                "try_known_keys": True,
                "exploit_rau": False,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"},
            respond_args={"status": 404},
        )
        module_test.set_expect_requests(
            expect_args={
                "method": "GET",
                "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx",
                "query_string": "dp=1",
            },
            respond_args={
                "response_data": "<div>Cannot deserialize dialog parameters. Please refresh the editor page.</div>",
            },
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"},
            respond_args={"status": 404},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/ChartImage.axd"},
            respond_args={"status": 404},
        )

        # Rig a keyed responder: KDF probe returns PBKDF1_MS banner, hash-key probes 500 until we
        # see the matching one, enc-key probes 500 until we see the matching one.
        module_test.httpserver.expect_request(
            "/App_Master/Telerik.Web.UI.DialogHandler.aspx", method="POST"
        ).respond_with_handler(_dh_knownkey_handler)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].dialoghandler_urls = [
            "App_Master/Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        known_key = any(
            e.type == "FINDING" and e.data.get("name") == "Telerik DialogHandler Known Key (CVE-2017-9248)"
            for e in events
        )
        assert known_key, "Expected Telerik DialogHandler Known Key finding (CVE-2017-9248)"


def _dh_knownkey_handler(request):
    """
    Model a PBKDF1_MS target with the first badsecrets hash key and encryption key.
    Distinguishes probe types by body length and by whether the payload passes
    the HMAC-SHA256 test carried by badsecrets' hashkey_probe_generator.
    """
    from werkzeug.wrappers import Response
    import hmac
    import hashlib
    import base64
    from urllib.parse import parse_qs
    from badsecrets import modules_loaded

    body = request.get_data().decode(errors="replace")
    params = parse_qs(body)
    probe = params.get("dialogParametersHolder", [""])[0]

    # KDF-mode probe: bare "AAAA" → PBKDF1_MS banner
    if probe == "AAAA":
        return Response(
            "Server Error: Length cannot be less than zero. Parameter name: length.",
            status=200,
        )

    hash_cls = modules_loaded["telerik_hashkey"]
    enc_cls = modules_loaded["telerik_encryptionkey"]
    hash_helper = hash_cls()
    enc_helper = enc_cls()

    hash_keys = list(hash_helper.prepare_keylist(include_machinekeys=False))
    enc_keys = list(enc_helper.prepare_keylist(include_machinekeys=False))
    target_hash_key = hash_keys[0]
    target_enc_key = enc_keys[0]

    # HMAC-verify the probe against target_hash_key. If it verifies AND the ciphertext prefix
    # is exactly base64(known 20-byte test string) that's the hashkey_probe_generator; otherwise
    # it's the encryptionkey probe (ciphertext = telerik_encrypt(b64("AAAAAAAAAAAAAAAAAAAA"))).
    if len(probe) < 44:
        return Response("", status=500)
    dp_enc = probe[:-44].encode()
    dp_hash = probe[-44:].encode()
    try:
        h = hmac.new(target_hash_key.encode(), dp_enc, hashlib.sha256)
        if base64.b64encode(h.digest()) != dp_hash:
            return Response("", status=500)
    except Exception:
        return Response("", status=500)

    # Hashkey verified. Is this the hashkey probe (unencrypted long dialog-params b64)?
    hashkey_test = b"EnableAsyncUpload,False,3,True;"
    try:
        decoded = base64.b64decode(dp_enc)
    except Exception:
        decoded = b""
    if decoded.startswith(hashkey_test):
        return Response(
            "The input data is not a complete block.",
            status=200,
        )

    # Otherwise this is the enckey probe. Verify enc_key by decrypting.
    try:
        ct_bytes = base64.b64decode(dp_enc)
    except Exception:
        return Response("", status=500)
    derived_key, derived_iv = enc_helper.telerik_derivekeys_PBKDF1_MS(target_enc_key)
    plaintext = enc_helper.telerik_decrypt(derived_key, derived_iv, ct_bytes)
    if plaintext is not None:
        return Response("Index was outside the bounds of the array.", status=200)
    return Response("", status=500)


class TestTelerikDialogHandler_includesubdirs(TestTelerik):
    targets = ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/temp/"]
    config_overrides = {
        "modules": {
            "telerik": {
                "include_subdirs": True,
            },
        }
    }
    modules_overrides = ["http", "telerik"]

    async def setup_before_prep(self, module_test):
        # Simulate NO SpellCheckHandler detection (not testing for that with this test)
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"}
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection (in /temp)
        expect_args = {"method": "GET", "uri": "/temp/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate /temp directory detection
        expect_args = {"method": "GET", "uri": "/temp/"}
        respond_args = {"response_data": "Temporary directory found"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].telerik_versions = ["2014.2.724", "2014.3.1024", "2015.1.204"]
        module_test.scan.modules["telerik"].dialoghandler_urls = [
            "App_Master/Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        # Check if the expected requests were made
        finding_count = sum(
            1 for e in events if e.type == "FINDING" and "Telerik DialogHandler detected" in e.data["description"]
        )
        assert finding_count == 2, "Expected 2 FINDING events (root and /temp), got {finding_count}"
