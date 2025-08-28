import importlib
from bbot.modules.base import BaseModule

from bbot.errors import InteractshError


class lightfuzz(BaseModule):
    watched_events = ["URL", "WEB_PARAMETER"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "web-thorough", "deadly"]

    options = {
        "force_common_headers": False,
        "enabled_submodules": ["sqli", "cmdi", "xss", "path", "ssti", "crypto", "serial"],
        "disable_post": False,
    }
    options_desc = {
        "force_common_headers": "Force emit commonly exploitable parameters that may be difficult to detect",
        "enabled_submodules": "A list of submodules to enable. Empty list enabled all modules.",
        "disable_post": "Disable processing of POST parameters, avoiding form submissions.",
    }

    meta = {
        "description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner",
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
        self.enabled_submodules = self.config.get("enabled_submodules")
        self.interactsh_disable = self.scan.config.get("interactsh_disable", False)
        self.submodules = {}

        if not self.enabled_submodules:
            return False, "Lightfuzz enabled without any submodules. Must enable at least one submodule."

        for submodule_name in self.enabled_submodules:
            try:
                submodule_module = importlib.import_module(f"bbot.modules.lightfuzz.submodules.{submodule_name}")
                submodule_class = getattr(submodule_module, submodule_name)
            except ImportError:
                return False, f"Invalid Lightfuzz submodule ({submodule_name}) specified in enabled_modules"
            self.submodules[submodule_name] = submodule_class

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
                if not details["event"]:
                    return
                # currently, this is only used by the cmdi submodule. Later, when other modules use it, we will need to store description data in the interactsh_subdomain_tags dictionary
                await self.emit_event(
                    {
                        "severity": "CRITICAL",
                        "host": str(details["event"].host),
                        "url": details["event"].data["url"],
                        "description": f"OS Command Injection (OOB Interaction) Type: [{details['type']}] Parameter Name: [{details['name']}] Probe: [{details['probe']}]",
                    },
                    "VULNERABILITY",
                    details["event"],
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    def _outgoing_dedup_hash(self, event):
        return hash(
            (
                "lightfuzz",
                str(event.host),
                event.data["url"],
                event.data["description"],
                event.data.get("type", ""),
                event.data.get("name", ""),
            )
        )

    async def run_submodule(self, submodule, event):
        submodule_instance = submodule(self, event)
        await submodule_instance.fuzz()
        if len(submodule_instance.results) > 0:
            for r in submodule_instance.results:
                event_data = {"host": str(event.host), "url": event.data["url"], "description": r["description"]}

                envelopes = getattr(event, "envelopes", None)
                envelope_summary = getattr(envelopes, "summary", None)
                if envelope_summary:
                    # Append the envelope summary to the description
                    event_data["description"] += f" Envelopes: [{envelope_summary}]"

                if r["type"] == "VULNERABILITY":
                    event_data["severity"] = r["severity"]
                await self.emit_event(
                    event_data,
                    r["type"],
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
                    "url": event.data,
                    "description": description,
                }
                await self.emit_event(data, "WEB_PARAMETER", event)

        elif event.type == "WEB_PARAMETER":
            # check connectivity to url
            connectivity_test = await self.helpers.request(event.data["url"], timeout=10)

            if connectivity_test:
                for submodule_name, submodule in self.submodules.items():
                    self.debug(f"Starting {submodule_name} fuzz()")
                    await self.run_submodule(submodule, event)
            else:
                self.debug(f"WEB_PARAMETER URL {event.data['url']} failed connectivity test, aborting")

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
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")

    # If we've disabled fuzzing POST parameters, back out of POSTPARAM WEB_PARAMETER events as quickly as possible
    async def filter_event(self, event):
        if event.type == "WEB_PARAMETER" and self.disable_post and event.data["type"] == "POSTPARAM":
            return False, "POST parameter disabled in lightfuzz module"
        return True

    @classmethod
    def help_text(self):
        # Call the base class help_text method
        base_help_text = super().help_text()

        import importlib

        submodules = {}
        for submodule_name in self.options.get("enabled_submodules", []):
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
