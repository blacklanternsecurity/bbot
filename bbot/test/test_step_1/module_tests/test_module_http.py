from .base import ModuleTestBase


class TestHTTP(ModuleTestBase):
    downstream_url = "https://blacklanternsecurity.fakedomain:1234/events"
    config_overrides = {
        "output_modules": {
            "http": {
                "url": downstream_url,
                "method": "PUT",
                "bearer": "auth_token",
                "username": "bbot_user",
                "password": "bbot_password",
            }
        }
    }

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            method="PUT", headers={"Authorization": "bearer auth_token"}, url=self.downstream_url
        )

    def check(self, module_test, events):
        pass
