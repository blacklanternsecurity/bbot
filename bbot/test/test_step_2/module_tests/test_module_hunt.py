from .base import ModuleTestBase


class TestHunt(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "hunt", "excavate"]
    config_overrides = {
        "interactsh_disable": True,
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": '<html><a href="/hackme.php?cipher=xor">ping</a></html>'}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "Found potentially interesting parameter. Name: [cipher] Parameter Type: [GETPARAM] Categories: [Insecure Cryptography] Original Value: [xor]"
            for e in events
        )


class TestHunt_Multiple(TestHunt):
    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": '<html><a href="/hackme.php?id=1234">ping</a></html>'}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "Found potentially interesting parameter. Name: [id] Parameter Type: [GETPARAM] Categories: [Insecure Direct Object Reference, SQL Injection, Server-Side Template Injection] Original Value: [1234]"
            for e in events
        )
