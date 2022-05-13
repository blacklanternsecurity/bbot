from .base import BaseModule
import re


class aspnet_viewstate(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    in_scope_only = False

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="(.+)"')

    def handle_event(self, event):

        result = self.helpers.request(event.data)
        if not result:
            self.debug(f"Could not connect to url {event.data}")
            return
        self.debug(f"Successfully connected to host")

        generator_match = self.generator_regex.search(result.text)
        viewstate_match = self.viewstate_regex.search(result.text)

        if generator_match and viewstate_match:
            generator = generator_match.group(1)
            viewstate = viewstate_match.group(1)
            self.debug(f"Discovered viewstate for URL {event.data}")
            self.emit_event(f"[{event.data}] Microsoft ASP.NET", "TECHNOLOGY", event, tags=["web"])
            command = [
                "mono",
                "/opt/blacklist3r/AspDotNetWrapper.exe",
                "--keypath",
                "/opt/blacklist3r/MachineKeys.txt",
                "--encrypteddata",
                f"{viewstate}",
                "--purpose=viewstate",
                f"--modifier={generator}",
                "--macdecode",
            ]
            output = self.helpers.run(command).stdout
            self.debug(f"blacklist3r output: {output}")
            if "Keys found!!" in output:
                for x in output.split("\n"):
                    if "DecryptionKey" in x:
                        solvedDecryption = x.split(":")[1]
                    if "ValidationKey" in x:
                        solvedValidation = x.split(":")[1]

                data = f"[CRITICAL] Known MachineKey found. URL: [{event.data}] EncryptionKey: [{solvedDecryption}] ValidationKey: [{solvedValidation}]"
                self.emit_event(data, "VULNERABILITY", event, tags=["critical"])
        else:
            self.debug("aspnet_viewstate viewstate not found")
