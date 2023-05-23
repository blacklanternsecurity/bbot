from .base import ModuleTestBase


class TestSecretsDB(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "secretsdb"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://raw.githubusercontent.com/blacklanternsecurity/secrets-patterns-db/master/db/rules-stable.yml",
            text="""patterns:
- pattern:
    confidence: 99
    name: Asymmetric Private Key
    regex: '-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'""",
        )
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "-----BEGIN PGP PRIVATE KEY BLOCK-----"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "FINDING" for e in events)
