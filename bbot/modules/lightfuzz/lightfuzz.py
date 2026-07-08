import importlib
from urllib.parse import urlparse

from bbot.modules.base import BaseModule
from bbot.core.helpers.async_helpers import NamedLock

from bbot.errors import InteractshError
from bbot.core.config.models import BaseModuleConfig, Field
from bbot.core.helpers.misc import get_waf_strings
from bbot.core.helpers.web.response_event import response_to_event_dict
from bbot.modules.lightfuzz.submodules.base import BaseLightfuzz
from bbot.modules.lightfuzz.submodules.serial import serial as _serial_submodule


class lightfuzz(BaseModule):
    watched_events = ["URL", "WEB_PARAMETER"]
    produced_events = ["FINDING", "HTTP_RESPONSE"]
    flags = ["active", "loud", "web-heavy", "invasive"]

    class Config(BaseModuleConfig):
        force_common_headers: bool = Field(
            False, description="Force emit commonly exploitable parameters that may be difficult to detect"
        )
        enabled_submodules: list[str] = Field(
            ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial", "esi", "ssrf"],
            description="A list of submodules to enable. Empty list enabled all modules.",
        )
        disable_post: bool = Field(
            False, description="Disable processing of POST parameters, avoiding form submissions."
        )
        try_post_as_get: bool = Field(
            False, description="For each POSTPARAM, also fuzz it as a GETPARAM (in addition to normal POST fuzzing)."
        )
        try_get_as_post: bool = Field(
            False, description="For each GETPARAM, also fuzz it as a POSTPARAM (in addition to normal GET fuzzing)."
        )
        avoid_wafs: bool = Field(
            True, description="Avoid running against confirmed WAFs, which are likely to block lightfuzz requests"
        )
        emit_baseline_responses: bool = Field(
            True,
            description="Emit canonical baseline responses as HTTP_RESPONSE events so excavate can mine them for new params/URLs.",
        )

    meta = {
        "description": "BBOT's DAST module — lightly fuzz web parameters discovered during recon for common vulnerability classes",
        "author": "@liquidsec",
        "created_date": "2024-06-28",
    }
    common_headers = ["x-forwarded-for", "user-agent"]
    in_scope_only = True

    _module_threads = 4

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None
        self.interactsh_domain = None
        self.disable_post = self.config.get("disable_post", False)
        self.try_post_as_get = self.config.get("try_post_as_get", False)
        self.try_get_as_post = self.config.get("try_get_as_post", False)
        self.enabled_submodules = self.config.get("enabled_submodules")
        self.interactsh_disable = self.scan.config.get("interactsh_disable", False)
        self.avoid_wafs = self.scan.config.get("avoid_wafs", True)
        self.emit_baseline_responses = self.config.get("emit_baseline_responses", True)
        self.submodules = {}
        # Per-event baseline cache so submodules with identical request signatures share one HttpCompare.
        self._baseline_cache = {}

        # Cross-event baseline_probe response cache: sibling fields of the same form produce identical requests.
        self._baseline_probe_response_cache = {}
        self._baseline_probe_response_cache_max = 200

        # Per-URL lock + cache so concurrent WEB_PARAMETERs for the same page share one connectivity GET
        # (servers that cycle session/CSRF tokens hand each racer a different token otherwise).
        self._connectivity_test_cache = {}
        self._connectivity_test_cache_max = 300
        self._connectivity_test_locks = NamedLock(max_size=200)

        if not self.enabled_submodules:
            return False, "Lightfuzz enabled without any submodules. Must enable at least one submodule."

        for submodule_name in self.enabled_submodules:
            try:
                submodule_module = importlib.import_module(f"bbot.modules.lightfuzz.submodules.{submodule_name}")
                submodule_class = getattr(submodule_module, submodule_name)
            except ImportError:
                return False, f"Invalid Lightfuzz submodule ({submodule_name}) specified in enabled_modules"
            self.submodules[submodule_name] = submodule_class

        waf_strings = get_waf_strings()
        self.waf_yara_rules = self.helpers.yara.compile_strings(waf_strings, nocase=True)
        # Serial submodule needs WAF + general error strings in one rule
        self.serial_general_error_yara_rules = self.helpers.yara.compile_strings(
            _serial_submodule.GENERAL_ERROR_STRINGS + waf_strings, nocase=True
        )

        interactsh_needed = any(submodule.uses_interactsh for submodule in self.submodules.values())
        if interactsh_needed and not self.interactsh_disable:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
                if not self.interactsh_domain:
                    self.warning("Interactsh failure: No domain returned from self.interactsh_instance.register()")
                    self.interactsh_instance = None
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                self.interactsh_instance = None
        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                details = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not details or not details.get("event"):
                    # Callback for a subdomain we didn't register, or whose
                    # tag entry is incomplete — ignore rather than NPE.
                    return
                protocol = r.get("protocol", "dns").lower()
                severity = details.get("severity", "HIGH")
                confidence = details.get("confidence", "CONFIRMED")
                # Allow submodules to specify alternative severity/confidence for DNS-only interactions
                if protocol == "dns":
                    severity = details.get("severity_dns", severity)
                    confidence = details.get("confidence_dns", confidence)
                description = f"{details['description']} Interaction Protocol: [{protocol}]"
                await self.emit_event(
                    {
                        "severity": severity,
                        "confidence": confidence,
                        "host": str(details["event"].host),
                        "url": details["event"].url,
                        "name": f"Lightfuzz - {details['name']}",
                        "description": description,
                    },
                    "FINDING",
                    details["event"],
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    async def _connectivity_test(self, prime_url):
        """Fire (or share) a connectivity GET against ``prime_url``; concurrent callers share one response."""
        cache = self._connectivity_test_cache
        if prime_url in cache:
            return cache[prime_url]
        async with self._connectivity_test_locks.lock(prime_url):
            if prime_url in cache:
                return cache[prime_url]
            response = await self.helpers.request(prime_url, timeout=10)
            if response is not None:
                if len(cache) >= self._connectivity_test_cache_max:
                    cache.pop(next(iter(cache)))
                cache[prime_url] = response
            return response

    @staticmethod
    def _baseline_request_signature(request_params):
        """Stable hashable signature of a baseline request (URL + method + body + cookies + headers)."""

        def _freeze(d):
            if not d:
                return ()
            try:
                return tuple(sorted((str(k), str(v)) for k, v in d.items()))
            except AttributeError:
                return (str(d),)

        return (
            request_params.get("method", "GET"),
            request_params.get("url", ""),
            _freeze(request_params.get("data")),
            _freeze(request_params.get("json")),
            _freeze(request_params.get("cookies")),
            _freeze(request_params.get("headers")),
        )

    def get_cached_baseline(self, event, signature):
        """Return a cached HttpCompare for (event, signature) if present, else None."""
        return self._baseline_cache.get(event.id, {}).get(signature)

    def store_cached_baseline(self, event, signature, http_compare):
        """Store an HttpCompare in the per-event baseline cache."""
        self._baseline_cache.setdefault(event.id, {})[signature] = http_compare

    async def emit_baseline_response(self, response, event, method):
        """Emit a baseline blasthttp Response as an HTTP_RESPONSE event so excavate can mine post-submit pages."""
        if not self.emit_baseline_responses:
            return
        if response is None:
            return
        try:
            parsed = urlparse(str(response.url))
            url_input = parsed.netloc or str(response.url)
            j = response_to_event_dict(response, url_input, method=method)
        except Exception as e:
            self.debug(f"Failed to build HTTP_RESPONSE dict from lightfuzz baseline: {e}")
            return
        await self.emit_event(
            j,
            "HTTP_RESPONSE",
            event,
            tags=["from-lightfuzz"],
            context="{module} emitted baseline response from canonical fuzzing probe",
        )

    def _outgoing_dedup_hash(self, event):
        if event.type == "FINDING":
            return hash(
                (
                    "lightfuzz",
                    str(event.host),
                    event.url,
                    event.data.get("description", ""),
                    event.data.get("type", ""),
                    event.data.get("name", ""),
                )
            )
        # Include body hash so dual baselines (same method+url, distinct bodies) both surface.
        body_hash = ""
        if isinstance(event.data, dict):
            response_hash = event.data.get("hash") or {}
            if isinstance(response_hash, dict):
                body_hash = response_hash.get("body_md5", "") or ""
        return hash(
            (
                "lightfuzz",
                event.type,
                str(event.host),
                event.url,
                event.data.get("method", "") if isinstance(event.data, dict) else "",
                body_hash,
            )
        )

    async def run_submodule(self, submodule, event):
        submodule_instance = submodule(self, event)
        await submodule_instance.fuzz()
        if len(submodule_instance.results) > 0:
            for r in submodule_instance.results:
                event_data = {
                    "host": str(event.host),
                    "url": event.url,
                    "name": r["name"],
                    "description": r["description"],
                }

                envelopes = getattr(event, "envelopes", None)
                envelope_summary = getattr(envelopes, "summary", None)
                if envelope_summary:
                    # Append the envelope summary to the description
                    event_data["description"] += f" Envelopes: [{envelope_summary}]"

                event_data["severity"] = r["severity"]
                event_data["confidence"] = r["confidence"]
                event_data["name"] = f"Lightfuzz - {r['name']}"
                await self.emit_event(
                    event_data,
                    "FINDING",
                    event,
                )

    async def handle_event(self, event):
        if event.type == "URL":
            if self.config.get("force_common_headers", False) is False:
                return False

            # If force_common_headers is True, we force the emission of a WEB_PARAMETER for each of the common headers to force fuzzing against them
            for h in self.common_headers:
                description = f"Speculative (Forced) Header [{h}]"
                data = {
                    "host": str(event.host),
                    "type": "HEADER",
                    "name": h,
                    "original_value": None,
                    "url": event.url,
                    "description": description,
                }
                await self.emit_event(data, "WEB_PARAMETER", event)

        elif event.type == "WEB_PARAMETER":
            # Mirror browser flow: GET the form's host page first to seed cookies/CSRF, then POST to action.
            host_url = event.data.get("host_url") if isinstance(event.data, dict) else None
            prime_url = host_url if host_url and host_url != event.url else event.url
            connectivity_test = await self._connectivity_test(prime_url)

            if connectivity_test:
                # Merge fresh Set-Cookie values from the connectivity GET into assigned_cookies.
                # Cookies the GET didn't re-issue (e.g. an unrelated auth cookie) are preserved.
                fresh_cookies = dict(getattr(connectivity_test, "cookies", {}) or {})
                if fresh_cookies:
                    merged = dict(event.data.get("assigned_cookies") or {})
                    merged.update(fresh_cookies)
                    event.data["assigned_cookies"] = merged

                try:
                    original_type = event.data["type"]

                    # Fire the canonical baseline once per WEB_PARAMETER so excavate can mine the
                    # post-submit page; later submodule baseline_probes hit the response cache.
                    if self.emit_baseline_responses:
                        prober = BaseLightfuzz(self, event)
                        try:
                            await prober.baseline_probe(cookies=event.data.get("assigned_cookies", {}) or {})
                        except Exception as e:
                            self.debug(f"module-level baseline_probe raised: {e}")

                    # Normal fuzzing pass (skipped for POSTPARAM if disable_post is True)
                    if not (self.disable_post and original_type == "POSTPARAM"):
                        for submodule_name, submodule in self.submodules.items():
                            self.debug(f"Starting {submodule_name} fuzz()")
                            await self.run_submodule(submodule, event)

                    # Additional pass: try POSTPARAM as GETPARAM
                    if self.try_post_as_get and original_type == "POSTPARAM":
                        event.data["type"] = "GETPARAM"
                        event.data["converted_from_post"] = True
                        for submodule_name, submodule in self.submodules.items():
                            self.debug(f"Starting {submodule_name} fuzz() (try_post_as_get)")
                            await self.run_submodule(submodule, event)

                    # Additional pass: try GETPARAM as POSTPARAM
                    if self.try_get_as_post and original_type == "GETPARAM":
                        event.data["type"] = "POSTPARAM"
                        event.data["converted_from_get"] = True
                        for submodule_name, submodule in self.submodules.items():
                            self.debug(f"Starting {submodule_name} fuzz() (try_get_as_post)")
                            await self.run_submodule(submodule, event)
                finally:
                    # Restore the original type so downstream consumers see the
                    # correct value after the conversion passes.
                    event.data["type"] = original_type
                    event.data.pop("converted_from_post", None)
                    event.data.pop("converted_from_get", None)
                    # Drop the per-event baseline cache once all submodules have run.
                    self._baseline_cache.pop(event.id, None)
            else:
                self.debug(f"WEB_PARAMETER URL {event.url} failed connectivity test, aborting")

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            self.debug("finish(): sleeping 5s before final interactsh poll")
            await self.helpers.sleep(5)
            try:
                results = await self.interactsh_instance.poll()
                self.debug(f"finish(): interactsh poll returned {len(results)} interaction(s)")
                for r in results:
                    protocol = r.get("protocol", "unknown")
                    full_id = r.get("full-id", "unknown")
                    self.debug(f"finish(): interactsh interaction: protocol={protocol}, full-id={full_id}")
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")

    async def filter_event(self, event):
        if await self._is_http_wildcard_host(event) is True:
            return False, "host is an HTTP wildcard responder"

        # Unless configured specifically to do so, avoid running against confirmed WAFs
        if self.avoid_wafs and "waf" in event.tags:
            # Use parsed_url.geturl() for both URL and WEB_PARAMETER events
            parsed_url = getattr(event, "parsed_url", None)
            url = parsed_url.geturl() if parsed_url else "unknown"
            self.debug(f"Skipping {event.type} because it is likely to be blocked by a WAF. URL: {url}")
            return False

        # Skip WEB_PARAMETERs on static-asset URLs (pdf, doc, xml, etc.) — fuzzing them is pointless
        if event.type == "WEB_PARAMETER":
            ext = getattr(event, "url_extension", None)
            if ext and ext in self.scan.config.get("url_extension_static", []):
                return False, f"skipping WEB_PARAMETER on static-asset URL (.{ext})"

        # If we've disabled fuzzing POST parameters, back out of POSTPARAM WEB_PARAMETER events as quickly as possible
        if event.type == "WEB_PARAMETER" and self.disable_post and event.data["type"] == "POSTPARAM":
            if not self.try_post_as_get:
                return False, "POST parameter disabled in lightfuzz module"
        return True

    @classmethod
    def help_text(cls):
        # Call the base class help_text method
        base_help_text = super().help_text()

        import importlib

        # classmethod: read defaults from the Config schema (instance config isn't available here)
        default_submodules = cls.Config.model_fields["enabled_submodules"].get_default(call_default_factory=True)
        if not isinstance(default_submodules, (list, tuple)):
            default_submodules = []

        submodules = {}
        for submodule_name in default_submodules:
            try:
                submodule_module = importlib.import_module(f"bbot.modules.lightfuzz.submodules.{submodule_name}")
                submodule_class = getattr(submodule_module, submodule_name)
                submodules[submodule_name] = submodule_class
            except ImportError:
                continue

        # Find all submodules
        submodules_info = "\nLightfuzz Submodules:\n"
        for submodule_name, submodule_class in submodules.items():
            try:
                friendly_name = getattr(submodule_class, "friendly_name", submodule_name)
                description = (
                    submodule_class.__doc__.strip() if submodule_class.__doc__ else "No description available"
                )
                indented_description = "      " + description.replace("\n", "\n      ")
                submodules_info += f"  - {submodule_name} ({friendly_name}):\n"
                submodules_info += f"{indented_description}\n\n"
            except AttributeError:
                continue

        # Combine the base help text with the submodules information
        return base_help_text + submodules_info
