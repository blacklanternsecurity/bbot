from lxml import etree
from bbot.modules.base import BaseModule


class dastardly(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "slow", "web-thorough"]
    meta = {"description": "Lightweight web application security scanner"}

    deps_pip = ["lxml~=4.9.2"]
    deps_ansible = [
        {
            "name": "Check if Docker is already installed",
            "command": "docker --version",
            "register": "docker_installed",
            "ignore_errors": True,
        },
        {
            "name": "Install Docker (Non-Debian)",
            "package": {"name": "docker", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] != 'Debian' and docker_installed.rc != 0",
        },
        {
            "name": "Install Docker (Debian)",
            "package": {
                "name": "docker.io",
                "state": "present",
            },
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian' and docker_installed.rc != 0",
        },
    ]
    per_hostport_only = True

    async def setup(self):
        await self.helpers.run("systemctl", "start", "docker", sudo=True)
        await self.helpers.run("docker", "pull", "public.ecr.aws/portswigger/dastardly:latest", sudo=True)
        self.output_dir = self.scan.home / "dastardly"
        self.helpers.mkdir(self.output_dir)
        return True

    async def filter_event(self, event):
        # Reject redirects. This helps to avoid scanning the same site twice.
        is_redirect = str(event.data["status_code"]).startswith("30")
        if is_redirect:
            return False, "URL is a redirect"
        return True

    async def handle_event(self, event):
        host = event.parsed._replace(path="/").geturl()
        self.verbose(f"Running Dastardly scan against {host}")
        command, output_file = self.construct_command(host)
        finished_proc = await self.helpers.run(command, sudo=True)
        self.debug(f'dastardly stdout: {getattr(finished_proc, "stdout", "")}')
        self.debug(f'dastardly stderr: {getattr(finished_proc, "stderr", "")}')
        for testsuite in self.parse_dastardly_xml(output_file):
            url = testsuite.endpoint
            for testcase in testsuite.testcases:
                for failure in testcase.failures:
                    if failure.severity == "Info":
                        await self.emit_event(
                            {
                                "host": str(event.host),
                                "url": url,
                                "description": failure.instance,
                            },
                            "FINDING",
                            event,
                        )
                    else:
                        await self.emit_event(
                            {
                                "severity": failure.severity,
                                "host": str(event.host),
                                "url": url,
                                "description": failure.instance,
                            },
                            "VULNERABILITY",
                            event,
                        )

    def construct_command(self, target):
        date_time = self.helpers.make_date()
        file_name = self.helpers.tagify(target)
        temp_path = self.output_dir / f"{date_time}_{file_name}.xml"
        command = [
            "docker",
            "run",
            "--user",
            "0",
            "--rm",
            "-v",
            f"{self.output_dir}:/dastardly",
            "-e",
            f"BURP_START_URL={target}",
            "-e",
            f"BURP_REPORT_FILE_PATH=/dastardly/{temp_path.name}",
            "public.ecr.aws/portswigger/dastardly:latest",
        ]
        return command, temp_path

    def parse_dastardly_xml(self, xml_file):
        try:
            with open(xml_file, "rb") as f:
                et = etree.parse(f)
                for testsuite in et.iter("testsuite"):
                    yield TestSuite(testsuite)
        except Exception as e:
            self.warning(f"Error parsing Dastardly XML at {xml_file}: {e}")


class Failure:
    def __init__(self, xml):
        self.etree = xml

        # instance information
        self.instance = self.etree.attrib.get("message", "")
        self.severity = self.etree.attrib.get("type", "")
        self.text = self.etree.text


class TestCase:
    def __init__(self, xml):
        self.etree = xml

        # title information
        self.title = self.etree.attrib.get("name", "")

        # findings / failures(as dastardly names them)
        self.failures = []
        for failure in self.etree.findall("failure"):
            self.failures.append(Failure(failure))


class TestSuite:
    def __init__(self, xml):
        self.etree = xml

        # endpoint information
        self.endpoint = self.etree.attrib.get("name", "")

        # test cases
        self.testcases = []
        for testcase in self.etree.findall("testcase"):
            self.testcases.append(TestCase(testcase))
