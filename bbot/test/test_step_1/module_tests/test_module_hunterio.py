from .base import ModuleTestBase


class TestHunterio(ModuleTestBase):
    config_overrides = {"modules": {"hunterio": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.hunter.io/v2/account?api_key=asdf",
            json={
                "data": {
                    "first_name": "jon",
                    "last_name": "snow",
                    "email": "jon@blacklanternsecurity.notreal",
                    "plan_name": "Starter",
                    "plan_level": 1,
                    "reset_date": "1917-05-23",
                    "team_id": 1234,
                    "calls": {
                        "_deprecation_notice": "Sums the searches and the verifications, giving an unprecise look of the available requests",
                        "used": 999,
                        "available": 2000,
                    },
                    "requests": {
                        "searches": {"used": 998, "available": 1000},
                        "verifications": {"used": 0, "available": 1000},
                    },
                }
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.hunter.io/v2/domain-search?domain=blacklanternsecurity.com&api_key=asdf&limit=100&offset=0",
            json={
                "data": {
                    "domain": "blacklanternsecurity.com",
                    "disposable": False,
                    "webmail": False,
                    "accept_all": False,
                    "pattern": "{first}",
                    "organization": "Black Lantern Security",
                    "description": None,
                    "twitter": None,
                    "facebook": None,
                    "linkedin": "https://linkedin.com/company/black-lantern-security",
                    "instagram": None,
                    "youtube": None,
                    "technologies": ["jekyll", "nginx"],
                    "country": "US",
                    "state": "CA",
                    "city": "Night City",
                    "postal_code": "12345",
                    "street": "123 Any St",
                    "emails": [
                        {
                            "value": "asdf@blacklanternsecurity.com",
                            "type": "generic",
                            "confidence": 77,
                            "sources": [
                                {
                                    "domain": "blacklanternsecurity.com",
                                    "uri": "http://blacklanternsecurity.com",
                                    "extracted_on": "2021-06-09",
                                    "last_seen_on": "2023-03-21",
                                    "still_on_page": True,
                                }
                            ],
                            "first_name": None,
                            "last_name": None,
                            "position": None,
                            "seniority": None,
                            "department": "support",
                            "linkedin": None,
                            "twitter": None,
                            "phone_number": None,
                            "verification": {"date": None, "status": None},
                        }
                    ],
                    "linked_domains": [],
                },
                "meta": {
                    "results": 1,
                    "limit": 100,
                    "offset": 0,
                    "params": {
                        "domain": "blacklanternsecurity.com",
                        "company": None,
                        "type": None,
                        "seniority": None,
                        "department": None,
                    },
                },
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf@blacklanternsecurity.com" for e in events), "Failed to detect email"
