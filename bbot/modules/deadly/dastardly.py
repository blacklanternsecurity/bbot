from lxml import etree
from bbot.modules.base import BaseModule


class dastardly(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive"]
    meta = {"description": "Lightweight web application security scanner"}

    deps_apt = ["docker.io"]
    deps_pip = ["lxml~=4.9.2"]
    deps_ansible = [
        {
            "name": "Pull the dastardly image",
            "docker_image": {
                "name": "public.ecr.aws/portswigger/dastardly:latest"
            },
        }
    ]
    in_scope_only = True

    async def setup(self):
        self.helpers.depsinstaller.ensure_root(message="Dastardly: docker requires root privileges")
        return True

    async def handle_event(self, event):
        host = str(event.data)
        command, output_file = self.construct_command(host)
        try:
            await self.helpers.run(command, sudo=True)
            for testsuite in self.parse_dastardly_xml(output_file):
                url = testcase.endpoint
                for testcase in testsuite.testcases:
                    for failure in testcase.failures:
                        message = failure.instance
                        detail = failure.text
                        if failure.severity == "Info":
                            self.emit_event(
                                {
                                    "host": str(event.host),
                                    "url": url,
                                    "description": message,
                                    "detail": detail,
                                },
                                "FINDING",
                                event,
                            )
                        else:
                            self.emit_event(
                                {
                                    "severity": severity,
                                    "host": str(event.host),
                                    "url": url,
                                    "description": message,
                                    "detail": detail,
                                },
                                "VULNERABILITY",
                                event,
                            )
        finally:
            output_file.unlink(missing_ok=True)

    def construct_command(self, target):
        temp_filename = self.helpers.temp_filename(extension="xml")
        command = [
            'docker',
            'run',
            '--user',
            '$(id -u)',
            '--rm',
            '-v',
            '$(pwd):/dastardly',
            '-e',
            'BURP_START_URL={target}',
            '-e',
            'BURP_REPORT_FILE_PATH=/dastardly/{temp_filename}',
            'public.ecr.aws/portswigger/dastardly:latest'
        ]
        return command, temp_filename

    def parse_dastardly_xml(self, xml_file):
        try:
            with open(xml_file, "rb") as f:
                et = etree.parse(f)
                for testsuite in et.iter("testsuite"):
                    yield TestSuite(testsuite)
        except Exception as e:
            self.warning(f"Error parsing Nmap XML at {xml_file}: {e}")

    async def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)

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
            self.testcases.append(Failure(failure))

class TestSuite:
    def __init__(self, xml):
        self.etree = xml

        # endpoint information
        self.endpoint = self.etree.attrib.get("name", "")

        # test cases
        self.testcases = []
        for testcase in self.etree.findall("testcase"):
            self.testcases.append(TestCase(testcase))