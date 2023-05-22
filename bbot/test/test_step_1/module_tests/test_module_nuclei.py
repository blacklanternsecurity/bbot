from .base import ModuleTestBase


class TestNucleiManual(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "excavate", "nuclei"]
    config_overrides = {
        "web_spider_distance": 1,
        "web_spider_depth": 1,
        "modules": {
            "nuclei": {
                "version": "2.9.4",
                "mode": "manual",
                "concurrency": 2,
                "ratelimit": 10,
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/http/miscellaneous/",
                "interactsh_disable": True,
                "directory_only": False,
            }
        },
    }

    test_html = """
    html>
 <head>
  <title>Index of /test</title>
 </head>
 <body>
<h1>Index of /test</h1>
  <table>
   <tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
   <tr><th colspan="3"><hr></th></tr>
<tr><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
</table>
<address>Apache/2.4.38 (Debian) Server at http://127.0.0.1:8888/testmultipleruns.html</address>
</body></html>
"""

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.test_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/testmultipleruns.html"}
        respond_args = {"response_data": "<html>Copyright 1984</html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        first_run_detect = False
        second_run_detect = False
        for e in events:
            if e.type == "FINDING":
                if "Directory listing enabled" in e.data["description"]:
                    first_run_detect = True
                elif "Copyright" in e.data["description"]:
                    second_run_detect = True
        assert first_run_detect
        assert second_run_detect


class TestNucleiSevere(TestNucleiManual):
    modules_overrides = ["httpx", "nuclei"]
    config_overrides = {
        "modules": {
            "nuclei": {
                "mode": "severe",
                "concurrency": 1,
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/vulnerabilities/generic/generic-linux-lfi.yaml",
            }
        },
        "interactsh_disable": True,
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/etc/passwd"}
        respond_args = {"response_data": "<html>root:.*:0:0:</html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "VULNERABILITY" and "Generic Linux - Local File Inclusion" in e.data["description"]
            for e in events
        )


class TestNucleiTechnology(TestNucleiManual):
    config_overrides = {
        "interactsh_disable": True,
        "modules": {"nuclei": {"mode": "technology", "concurrency": 2, "tags": "apache"}},
    }

    async def setup_before_prep(self, module_test):
        self.caplog = module_test.request_fixture.getfixturevalue("caplog")
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": "<html><Directory></Directory></html>",
            "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        if "Using Interactsh Server" in self.caplog.text:
            return False
        assert any(e.type == "FINDING" and "apache" in e.data["description"] for e in events)


class TestNucleiBudget(TestNucleiManual):
    config_overrides = {
        "modules": {
            "nuclei": {
                "mode": "budget",
                "concurrency": 1,
                "tags": "spiderfoot",
                "templates": "/tmp/.bbot_test/tools/nuclei-templates/exposed-panels/spiderfoot.yaml",
                "interactsh_disable": True,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "<html><title>SpiderFoot</title><p>support@spiderfoot.net</p></html>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "FINDING" and "SpiderFoot" in e.data["description"] for e in events)
