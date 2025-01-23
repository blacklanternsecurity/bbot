from lxml import etree
from bbot.modules.base import BaseModule


class dastardly(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "slow", "web-thorough"]
    meta = {
        "description": "Lightweight web application security scanner",
        "created_date": "2023-12-11",
        "author": "@domwhewell-sage",
    }

    deps_pip = ["lxml~=5.3.0"]
    deps_common = ["docker"]
    per_hostport_only = True

    default_discovery_context = "{module} performed a light web scan against {event.parent.data['url']} and discovered {event.data['description']} at {event.data['url']}"

    async def setup(self):
        await self.run_process("systemctl", "start", "docker", sudo=True)
        await self.run_process("docker", "pull", "public.ecr.aws/portswigger/dastardly:latest", sudo=True)
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
        host = event.parsed_url._replace(path="/").geturl()
        self.verbose(f"Running Dastardly scan against {host}")
        command, output_file = self.construct_command(host)
        finished_proc = await self.run_process(command, sudo=True)
        self.debug(f"dastardly stdout: {getattr(finished_proc, 'stdout', '')}")
        self.debug(f"dastardly stderr: {getattr(finished_proc, 'stderr', '')}")
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
                            context=f"{{module}} executed web scan against {host} and identified {{event.type}}: {failure.instance}",
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
                            context=f"{{module}} executed web scan against {host} and identified {failure.severity.lower()} {{event.type}}: {failure.instance}",
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
                et = etree.parse(f, parser=etree.XMLParser(recover=True, resolve_entities=False))
                for testsuite in et.iter("testsuite"):
                    yield TestSuite(testsuite)
        except FileNotFoundError:
            self.debug(f"Could not find Dastardly XML file at {xml_file}")
        except OSError as e:
            self.verbose(f"Error opening Dastardly XML file at {xml_file}: {e}")
        except etree.ParseError as e:
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
