import json
from werkzeug import Response

from .base import ModuleTestBase


class TestDastardly(ModuleTestBase):
    targets = ["http://127.0.0.1:5556/"]
    modules_overrides = ["httpx", "dastardly"]

    web_response = """<!DOCTYPE html>
    <html>
    <body>
        <a href="/test?test=yes">visit this<a/>
    </body>
    </html>"""

    def xss_handler(self, request):
        response = f"""<!DOCTYPE html>
    <html>
    <head>
        <title>Email Form</title>
    </head>
    <body>
        {request.args.get("test", "")}
    </body>
    </html>"""
        return Response(response, content_type="text/html")

    async def get_docker_ip(self, module_test):
        docker_ip = "172.17.0.1"
        try:
            ip_output = await module_test.scan.helpers.run(["ip", "-j", "-4", "a", "show", "dev", "docker0"])
            interface_json = json.loads(ip_output.stdout)
            docker_ip = interface_json[0]["addr_info"][0]["local"]
        except Exception:
            pass
        return docker_ip

    async def setup_after_prep(self, module_test):
        httpserver = module_test.request_fixture.getfixturevalue("bbot_httpserver_allinterfaces")
        httpserver.expect_request("/").respond_with_data(self.web_response)
        httpserver.expect_request("/test").respond_with_handler(self.xss_handler)

        # get docker IP
        docker_ip = await self.get_docker_ip(module_test)
        module_test.scan.target.add(docker_ip)

        # replace 127.0.0.1 with docker host IP to allow dastardly access to local http server
        old_filter_event = module_test.module.filter_event

        def new_filter_event(event):
            self.new_url = f"http://{docker_ip}:5556/"
            event.data["url"] = self.new_url
            event.parsed_url = module_test.scan.helpers.urlparse(self.new_url)
            return old_filter_event(event)

        module_test.monkeypatch.setattr(module_test.module, "filter_event", new_filter_event)

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "VULNERABILITY"
                and f"{self.new_url}test" in e.data["description"]
                and "Cross-site scripting".lower() in e.data["description"].lower()
            ]
        )
