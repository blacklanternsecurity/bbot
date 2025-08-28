from .base import ModuleTestBase


class TestDehashed(ModuleTestBase):
    modules_overrides = ["dehashed", "speculate"]
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"dehashed": {"api_key": "deadbeef"}},
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "4363462346",
                        "email": ["bob@blacklanternsecurity.com"],
                        "ip_address": ["127.0.0.9"],
                        "username": ["bob@bob.com"],
                        "hashed_password": ["$2a$12$pVmwJ7pXEr3mE.DmCCE4fOUDdeadbeefd2KuCy/tq1ZUFyEOH2bve"],
                        "name": ["Bob Smith"],
                        "phone": ["+91283423839"],
                        "database_name": "eatstreet",
                        "raw_record": {"le_only": True, "unstructured": True},
                    },
                    {
                        "id": "234623453454",
                        "email": ["tim@blacklanternsecurity.com"],
                        "username": ["timmy"],
                        "password": ["TimTamSlam69"],
                        "name": "Tim Tam",
                        "phone": ["+123455667"],
                        "database_name": "eatstreet",
                    },
                ],
                "took": "61ms",
                "total": 2,
            },
        )
        await module_test.mock_dns(
            {
                "bob.com": {"A": ["127.0.0.1"]},
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        assert len(events) == 12
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com"])
        assert 1 == len([e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "bob@bob.com"
                and e.scope_distance == 1
                and "affiliate" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "bob.com" and e.scope_distance == 1 and "affiliate" in e.tags
            ]
        )
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "bob@blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "USERNAME"
                and e.data == "bob@blacklanternsecurity.com:bob@bob.com"
                and e.parent.data == "bob@blacklanternsecurity.com"
            ]
        )
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "tim@blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data
                == "bob@blacklanternsecurity.com:$2a$12$pVmwJ7pXEr3mE.DmCCE4fOUDdeadbeefd2KuCy/tq1ZUFyEOH2bve"
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "PASSWORD" and e.data == "tim@blacklanternsecurity.com:TimTamSlam69"]
        )
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "tim@blacklanternsecurity.com:timmy"])


class TestDehashedBadEmail(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "EZxg4Lz-INLUt6uRXZaV",
                        "email": ["foo.example.com"],
                        "database_name": "Collections",
                    },
                ],
                "took": "41ms",
                "total": 1,
            },
        )

    def check(self, module_test, events):
        debug_log_content = open(module_test.scan.home / "debug.log").read()
        assert "Invalid email from dehashed.com: foo.example.com" in debug_log_content


class TestDehashedHTTPError(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={"error": "issue with request body"},
            status_code=400,
        )

    def check(self, module_test, events):
        scan_log_content = open(module_test.scan.home / "scan.log").read()
        assert (
            'Error retrieving results from dehashed.com (status code 400): {"error":"issue with request body"}'
            in scan_log_content
        )


class TestDehashedTooManyResults(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "VXhNxj46SGsW4Lworh-G",
                        "email": ["bob@bob.com"],
                        "database_name": "Collections",
                    },
                ],
                "took": "40ms",
                "total": 10001,
            },
        )

    def check(self, module_test, events):
        scan_log_content = open(module_test.scan.home / "scan.log").read()
        assert "has 10,001 results in Dehashed. The API can only process the first 10,000 results." in scan_log_content
