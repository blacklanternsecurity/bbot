from .base import ModuleTestBase


class TestFullhunt(ModuleTestBase):
    config_overrides = {"modules": {"fullhunt": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://fullhunt.io/api/v1/auth/status",
            match_headers={"x-api-key": "asdf"},
            json={
                "message": "",
                "status": 200,
                "user": {
                    "company": "nightwatch",
                    "email": "jonsnow@nightwatch.notreal",
                    "first_name": "Jon",
                    "last_name": "Snow",
                    "plan": "free",
                },
                "user_credits": {
                    "credits_usage": 0,
                    "max_results_per_request": 3000,
                    "remaining_credits": 100,
                    "total_credits_per_month": 100,
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://fullhunt.io/api/v1/domain/blacklanternsecurity.com/subdomains",
            match_headers={"x-api-key": "asdf"},
            json={
                "domain": "blacklanternsecurity.com",
                "hosts": [
                    "asdf.blacklanternsecurity.com",
                ],
                "message": "",
                "metadata": {
                    "all_results_count": 11,
                    "available_results_for_user": 11,
                    "domain": "blacklanternsecurity.com",
                    "last_scanned": 1647083421,
                    "max_results_for_user": 3000,
                    "timestamp": 1684541940,
                    "user_plan": "free",
                },
                "status": 200,
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
