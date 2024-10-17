from .base import ModuleTestBase


credshed_auth_response = {
    "access_token": "big_access_token",
    "login": True,
}


credshed_response = {
    "accounts": [
        {
            "e": "bob@blacklanternsecurity.com",
            "h": [],
            "m": "hello my name is bob",
            "p": "",
            "s": [121562],
            "u": "",
        },
        {
            "e": "judy@blacklanternsecurity.com",
            "h": [
                "539FE8942DEADBEEFBC49E6EB2F175AC",
                "D2D8F0E9A4A2DEADBEEF1AC80F36D61F",
                "$2a$12$SHIC49jLIwsobdeadbeefuWb2BKWHUOk2yhpD77A0itiZI1vJqXHm",
            ],
            "m": "hello my name is judy",
            "p": "",
            "s": [80437],
            "u": "",
        },
        {
            "e": "tim@blacklanternsecurity.com",
            "h": [],
            "m": "hello my name is tim",
            "p": "TimTamSlam69",
            "s": [80437],
            "u": "tim",
        },
    ],
    "stats": {
        "accounts_searched": 9820758365,
        "elapsed": "0.00",
        "limit": 1000,
        "query": "blacklanternsecurity.com",
        "query_type": "domain",
        "sources_searched": 129957,
        "total_count": 3,
        "unique_count": 3,
    },
}


class TestCredshed(ModuleTestBase):
    config_overrides = {
        "modules": {"credshed": {"username": "admin", "password": "password", "credshed_url": "https://credshed.com"}}
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://credshed.com/api/auth",
            json=credshed_auth_response,
            method="POST",
        )
        module_test.httpx_mock.add_response(
            url=f"https://credshed.com/api/search",
            json=credshed_response,
            method="POST",
        )

    def check(self, module_test, events):
        assert len(events) == 11
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "bob@blacklanternsecurity.com"])
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "judy@blacklanternsecurity.com"])
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "tim@blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data == "judy@blacklanternsecurity.com:539FE8942DEADBEEFBC49E6EB2F175AC"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data == "judy@blacklanternsecurity.com:D2D8F0E9A4A2DEADBEEF1AC80F36D61F"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data
                == "judy@blacklanternsecurity.com:$2a$12$SHIC49jLIwsobdeadbeefuWb2BKWHUOk2yhpD77A0itiZI1vJqXHm"
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "PASSWORD" and e.data == "tim@blacklanternsecurity.com:TimTamSlam69"]
        )
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "tim@blacklanternsecurity.com:tim"])
