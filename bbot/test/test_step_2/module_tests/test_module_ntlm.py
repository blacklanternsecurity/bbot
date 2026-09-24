from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestNTLM(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "ntlm"]
    config_overrides = {"modules": {"ntlm": {"try_all": True}}}

    async def setup_after_prep(self, module_test):
        request_args = {"uri": "/", "headers": {"test": "header"}}
        module_test.set_expect_requests(request_args, {})
        request_args = {
            "uri": "/oab/",
            "headers": {"Authorization": "NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw=="},
        }
        respond_args = {
            "headers": {
                "WWW-Authenticate": "NTLM TlRMTVNTUAACAAAABgAGADgAAAAVgoni89aZT4Q0mH0AAAAAAAAAAHYAdgA+AAAABgGxHQAAAA9WAE4ATwACAAYAVgBOAE8AAQAKAEUAWABDADAAMQAEABIAdgBuAG8ALgBsAG8AYwBhAGwAAwAeAEUAWABDADAAMQAuAHYAbgBvAC4AbABvAGMAYQBsAAUAEgB2AG4AbwAuAGwAbwBjAGEAbAAHAAgAXxo0p/6L2QEAAAAA"
            }
        }
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        assert any(e.type == "FINDING" and "EXC01.vno.local" in e.data["description"] for e in events)
