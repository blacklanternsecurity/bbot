from bbot.modules.base import BaseModule
import re


class aspnet_viewstate(BaseModule):

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "web"]
    meta = {"description": "Parse web pages for viewstates and check them against blacklist3r"}

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="([^"]+)"')

    deps_ansible = [
        {
            "name": "apt_key",
            "become": True,
            "apt_key": {
                "keyserver": "hkp://keyserver.ubuntu.com:80",
                "id": "3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF",
            },
            "when": """ansible_facts['os_family'] == 'Debian'""",
        },
        {
            "name": "Add Mono Repo",
            "become": True,
            "apt_repository": {"repo": "deb https://download.mono-project.com/repo/ubuntu stable-focal main"},
            "when": """ansible_facts['os_family'] == 'Debian'""",
        },
        {
            "name": "Install mono-devel (Debian, RedHat)",
            "become": True,
            "package": {"name": ["mono-devel", "zip"], "state": "latest"},
            "when": """ansible_facts['os_family'] in ['Debian', 'RedHat']""",
        },
        {
            "name": "Install mono (Archlinux)",
            "become": True,
            "package": {"name": "mono", "state": "latest"},
            "when": """ansible_facts['os_family'] == 'Archlinux'""",
        },
        {"name": "Create blacklist3r dir", "file": {"state": "directory", "path": "{BBOT_TOOLS}/blacklist3r/"}},
        {
            "name": "Unarchive blacklist3r",
            "unarchive": {
                "src": "https://github.com/NotSoSecure/Blacklist3r/releases/download/4.0/AspDotNetWrapper.zip",
                "include": ["MachineKeys.txt", "CommandLine.dll", "AspDotNetWrapper.exe"],
                "dest": "{BBOT_TOOLS}/blacklist3r/",
                "remote_src": True,
            },
        },
    ]

    def handle_event(self, event):

        generator_match = self.generator_regex.search(event.data.get("response-body", ""))
        viewstate_match = self.viewstate_regex.search(event.data.get("response-body", ""))

        if generator_match and viewstate_match:
            generator = generator_match.group(1)
            viewstate = viewstate_match.group(1)
            self.debug(f"Discovered viewstate for URL {event.data['url']}")
            self.emit_event(
                {"technology": "asp", "host": str(event.host), "url": event.data["url"]}, "TECHNOLOGY", event
            )
            self.emit_event(
                {"technology": "iis", "host": str(event.host), "url": event.data["url"]}, "TECHNOLOGY", event
            )
            tool_path = self.scan.helpers.tools_dir / "blacklist3r"
            command = [
                "mono",
                tool_path / "AspDotNetWrapper.exe",
                "--keypath",
                tool_path / "MachineKeys.txt",
                "--encrypteddata",
                f"{viewstate}",
                "--purpose=viewstate",
                f"--modifier={generator}",
                "--macdecode",
            ]
            output = self.helpers.run(command).stdout
            self.debug(f"blacklist3r output: {output}")
            if "Keys found!!" in output:
                for x in output.splitlines():
                    if "DecryptionKey" in x:
                        solvedDecryption = x.split(":")[1]
                    if "ValidationKey" in x:
                        solvedValidation = x.split(":")[1]

                description = (
                    f"Known MachineKey found. EncryptionKey: [{solvedDecryption}] ValidationKey: [{solvedValidation}]"
                )
                event_data = {
                    "severity": "CRITICAL",
                    "description": description,
                    "host": str(event.host),
                    "url": event.data["url"],
                }
                self.emit_event(event_data, "VULNERABILITY", event)
        else:
            self.debug("aspnet_viewstate viewstate not found")
