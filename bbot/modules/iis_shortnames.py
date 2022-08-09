from bbot.modules.base import BaseModule


class iis_shortnames(BaseModule):

    watched_events = ["URL"]
    produced_events = ["URL_HINT"]
    flags = ["active", "safe"]
    meta = {"description": "Check for IIS shortname vulnerability"}
    options = {"detect_only": True, "threads": 8}
    options_desc = {
        "detect_only": "Only detect the vulnerability and do not run the shortname scanner",
        "threads": "the number of threads to run concurrently when executing the IIS shortname scanner",
    }
    in_scope_only = True

    deps_ansible = [
        {
            "name": "Install Java JRE (Debian)",
            "become": True,
            "package": {"name": "default-jre", "state": "latest"},
            "when": """ansible_facts['os_family'] == 'Debian'""",
        },
        {
            "name": "Install Java JRE (RedHat)",
            "become": True,
            "package": {"name": "java-latest-openjdk", "state": "latest"},
            "when": """ansible_facts['os_family'] == 'RedHat'""",
        },
        {
            "name": "Install Java JRE (Archlinux)",
            "package": {"name": "jre-openjdk", "state": "present"},
            "become": True,
            "when": """ansible_facts['os_family'] == 'Archlinux'""",
        },
    ]

    def setup(self):
        iis_shortname_jar = "https://github.com/irsdl/IIS-ShortName-Scanner/raw/master/iis_shortname_scanner.jar"
        iis_shortname_config = "https://raw.githubusercontent.com/irsdl/IIS-ShortName-Scanner/master/config.xml"
        self.iis_scanner_jar = self.helpers.download(iis_shortname_jar, cache_hrs=720)
        self.iis_scanner_config = self.helpers.download(iis_shortname_config, cache_hrs=720)
        if self.iis_scanner_jar and self.iis_scanner_config:
            return True
        return False

    def handle_event(self, event):

        normalized_url = event.data.rstrip("/") + "/"
        result = self.detect(normalized_url)

        if result:
            description = f"IIS Shortname Vulnerability"
            self.emit_event(
                {"severity": "LOW", "host": str(event.host), "url": normalized_url, "description": description},
                "VULNERABILITY",
                event,
            )
            if not self.config.get("detect_only"):
                command = [
                    "java",
                    "-jar",
                    self.iis_scanner_jar,
                    "0",
                    str(self.config.get("threads", 8)),
                    normalized_url,
                    self.iis_scanner_config,
                ]
                output = self.helpers.run(command).stdout
                self.debug(output)
                discovered_directories, discovered_files = self.shortname_parse(output)
                for d in discovered_directories:
                    if d[-2] == "~":
                        d = d.split("~")[:-1][0]
                    self.emit_event(normalized_url + d, "URL_HINT", event, tags=["directory"])
                for f in discovered_files:
                    if f[-2] == "~":
                        f = f.split("~")[:-1][0]
                    self.emit_event(normalized_url + f, "URL_HINT", event, tags=["file"])

    def detect(self, url):

        detected = False
        http_methods = ["GET", "OPTIONS", "DEBUG"]
        for http_method in http_methods:
            dir_name = self.helpers.rand_string(8)
            file_name = self.helpers.rand_string(1)
            control_url = url.rstrip("/") + "/" + f"{dir_name}*~1*/{file_name}.aspx"
            control = self.helpers.request(control_url, method=http_method)
            test_url = url.rstrip("/") + "/" + f"*~1*/{file_name}.aspx"
            test = self.helpers.request(test_url, method=http_method)
            if (control != None) and (test != None):
                if (control.status_code != 404) and (test.status_code == 404):
                    detected = True
        return detected

    def shortname_parse(self, output):
        discovered_directories = []
        discovered_files = []
        parseLines = output.split("\n")
        inDirectories = False
        inFiles = False
        for idx, line in enumerate(parseLines):
            if "Identified directories" in line:
                inDirectories = True
            elif "Indentified files" in line:
                inFiles = True
                inDirectories = False
            elif ":" in line:
                pass
            elif "Actual" in line:
                pass
            else:
                if inFiles == True:
                    if len(line) > 0:
                        shortname = line.split(" ")[-1].split(".")[0].split("~")[0]
                        extension = line.split(" ")[-1].split(".")[1]
                        if "?" not in extension:
                            discovered_files.append(f"{shortname}.{extension}".lower())

                elif inDirectories == True:
                    if len(line) > 0:
                        shortname = line.split(" ")[-1]
                        discovered_directories.append(shortname.lower())
        return discovered_directories, discovered_files
