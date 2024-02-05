from .base import ModuleTestBase


class TestNewsletters(ModuleTestBase):
    targets = ["blacklanternsecurity.com", "futureparty.com"]
    modules_overrides = ["speculate", "httpx", "newsletters"]

    config_overrides = {}

    def check(self, module_test, events):
        newsletter = False
        for event in events:
            if event.type == "NEWSLETTER":
                newsletter = True
        assert newsletter, "No NEWSLETTER emitted"
