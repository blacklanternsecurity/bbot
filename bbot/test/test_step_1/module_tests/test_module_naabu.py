from .base import ModuleTestBase


class TestNaabu(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" for e in events)
