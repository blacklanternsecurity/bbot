from .base import ModuleTestBase


class TestPortfilter_disabled(ModuleTestBase):
    modules_overrides = []

    async def setup_before_prep(self, module_test):
        from bbot.modules.base import BaseModule

        class DummyModule(BaseModule):
            _name = "dummy_module"
            watched_events = ["DNS_NAME"]

            async def handle_event(self, event):
                if event.type == "DNS_NAME" and event.data == "blacklanternsecurity.com":
                    await self.emit_event(
                        "www.blacklanternsecurity.com:443",
                        "OPEN_TCP_PORT",
                        parent=event,
                        tags=["cdn-ip", "cdn-amazon"],
                    )
                    # when portfilter is enabled, this should be filtered out
                    await self.emit_event(
                        "www.blacklanternsecurity.com:8080",
                        "OPEN_TCP_PORT",
                        parent=event,
                        tags=["cdn-ip", "cdn-amazon"],
                    )
                    await self.emit_event("www.blacklanternsecurity.com:21", "OPEN_TCP_PORT", parent=event)

        module_test.scan.modules["dummy_module"] = DummyModule(module_test.scan)

    def check(self, module_test, events):
        open_ports = {event.data for event in events if event.type == "OPEN_TCP_PORT"}
        assert open_ports == {
            "www.blacklanternsecurity.com:443",
            "www.blacklanternsecurity.com:8080",
            "www.blacklanternsecurity.com:21",
        }


class TestPortfilter_enabled(TestPortfilter_disabled):
    modules_overrides = ["portfilter"]

    def check(self, module_test, events):
        open_ports = {event.data for event in events if event.type == "OPEN_TCP_PORT"}
        # we should be missing the 8080 port because it's a CDN and not in portfilter's allowed list of open ports
        assert open_ports == {"www.blacklanternsecurity.com:443", "www.blacklanternsecurity.com:21"}
