from .base import ModuleTestBase


class TestDastardly(ModuleTestBase):
    targets = ["ginandjuice.shop"]
    modules_overrides = ["nmap", "httpx", "dastardly"]

    def check(self, module_test, events):
        reflected_xss = False
        vulnerable_js = False
        for e in events:
            if e.type == "VULNERABILITY":
                if "Cross-site scripting (reflected)" in e.data["description"]:
                    reflected_xss = True
            if e.type == "VULNERABILITY":
                if "Vulnerable JavaScript dependency" in e.data["description"]:
                    vulnerable_js = True
        assert reflected_xss
        assert vulnerable_js
