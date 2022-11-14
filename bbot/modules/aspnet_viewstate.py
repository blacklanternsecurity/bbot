from .base import BaseModule
import re
from badsecrets import modules_loaded

ASPNET_Viewstate = modules_loaded["aspnet_viewstate"]


class aspnet_viewstate(BaseModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Parse web pages for viewstates and check them against blacklist3r"}

    deps_pip = ["badsecrets"]

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="(.+)"')

    def handle_event(self, event):

        resp_body = event.data.get("body", None)
        if resp_body:
            generator_match = self.generator_regex.search(resp_body)
            viewstate_match = self.viewstate_regex.search(resp_body)

            if generator_match and viewstate_match:
                generator = generator_match.group(1)
                viewstate = viewstate_match.group(1)
                self.debug(f"Discovered viewstate for URL {event.data['url']}")
                self.emit_event(
                    {"technology": "asp", "url": event.data["url"], "host": str(event.host)}, "TECHNOLOGY", event
                )
                self.emit_event(
                    {"technology": "iis", "url": event.data["url"], "host": str(event.host)}, "TECHNOLOGY", event
                )

                x = ASPNET_Viewstate()
                self.hugesuccess(viewstate)
                self.hugesuccess(generator)
                r = x.check_secret(viewstate, generator)
                if r:
                    data = {
                        "severity": "CRITICAL",
                        "description": f"Known MachineKey found. EncryptionKey: [{r.get('encryptionKey','N/A')}], Encryption Algorithm: [{r.get('encryptionAlgo','N/A')}] ValidationKey: [{r.get('validationKey')}] ValidationAlgo:  [{r.get('validationAlgo')}]",
                        "url": event.data["url"],
                        "host": str(event.host),
                    }
                    self.emit_event(data, "VULNERABILITY", event)
            else:
                self.debug("aspnet_viewstate viewstate not found")
