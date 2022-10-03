from .base import BaseModule
import re


class aspnet_viewstate(BaseModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Parse web pages for viewstates and check them against blacklist3r"}

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="(.+)"')

    deps_ansible = [
        {
            "name": "Install mono (Debian)",
            "become": True,
            "package": {"name": ["mono-complete"], "state": "latest"},
            "when": """ansible_facts['os_family'] == 'Debian'""",
        },
        {
            "name": "Install mono (Redhat)",
            "become": True,
            "package": {"name": ["mono-complete"], "state": "latest"},
            "when": """ansible_facts['os_family'] == 'RedHat'""",
        },
        {
            "name": "Install mono (Archlinux)",
            "become": True,
            "package": {"name": ["mono"], "state": "latest"},
            "when": """ansible_facts['os_family'] == 'Archlinux'""",
        },
        {"name": "Create blacklist3r dir", "file": {"state": "directory", "path": "#{BBOT_TOOLS}/blacklist3r/"}},
        {
            "name": "Unarchive blacklist3r",
            "unarchive": {
                "src": "https://github.com/NotSoSecure/Blacklist3r/releases/download/4.0/AspDotNetWrapper.zip",
                "include": ["CommandLine.dll", "AspDotNetWrapper.exe"],
                "dest": "#{BBOT_TOOLS}/blacklist3r/",
                "remote_src": True,
            },
        },
        {
            "name": "Download MachineKeys.txt",
            "get_url": {
                "src": "https://raw.githubusercontent.com/NotSoSecure/Blacklist3r/master/MachineKey/AspDotNetWrapper/AspDotNetWrapper/Resource/MachineKeys.txt",
                "dest": "#{BBOT_TOOLS}/blacklist3r/",
            },
        },
    ]

    def handle_event(self, event):

        resp_body = event.data.get("response-body", None)
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
                tool_path = self.scan.helpers.tools_dir / "blacklist3r/"
                command = [
                    "mono",
                    f"{tool_path}/AspDotNetWrapper.exe",
                    "--keypath",
                    f"{tool_path}/MachineKeys.txt",
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

                    data = {
                        "severity": "CRITICAL",
                        "description": f"Known MachineKey found. EncryptionKey: [{solvedDecryption}], ValidationKey: [{solvedValidation}]",
                        "url": event.data["url"],
                        "host": str(event.host),
                    }
                    self.emit_event(data, "VULNERABILITY", event)
            else:
                self.debug("aspnet_viewstate viewstate not found")
