from .base import BaseModule
import re


class aspnet_viewstate(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="(.+)"')

    deps_ansible = [
        {
            "name": "apt_key",
            "become": True,
            "apt_key": {
                "keyserver": "hkp://keyserver.ubuntu.com:80",
                "id": "3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF",
            },
        },
        {
            "name": "Add Mono Repo",
            "become": True,
            "apt_repository": {"repo": "deb https://download.mono-project.com/repo/ubuntu stable-focal main"},
        },
        {
            "name": "Install mono-devel",
            "apt": {"name": ["mono-devel", "zip"], "state": "latest", "update_cache": True},
        },
        {"name": "Create blacklist3r dir", "file": {"state": "directory", "path": "${BBOT_TOOLS}/blacklist3r/"}},
        {
            "name": "Unarchive blacklist3r",
            "unarchive": {
                "src": "https://github.com/NotSoSecure/Blacklist3r/releases/download/4.0/AspDotNetWrapper.zip",
                "include": ["MachineKeys.txt", "CommandLine.dll", "AspDotNetWrapper.exe"],
                "dest": "${BBOT_TOOLS}/blacklist3r/",
                "remote_src": True,
            },
        },
    ]

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

                data = f"[CRITICAL] Known MachineKey found. URL: [{event.data}] EncryptionKey: [{solvedDecryption}] ValidationKey: [{solvedValidation}]"
                self.emit_event(data, "VULNERABILITY", event, tags=["critical"])
        else:
            self.debug("aspnet_viewstate viewstate not found")
