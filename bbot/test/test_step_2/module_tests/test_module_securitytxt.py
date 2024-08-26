from .base import ModuleTestBase


class TestSecurityTxt(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]
    modules_overrides = ["securitytxt", "speculate"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://blacklanternsecurity.notreal/.well-known/security.txt",
            text="-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nContact: mailto:joe.smith@blacklanternsecurity.notreal\nContact: mailto:vdp@example.com\nContact: https://vdp.example.com\nExpires: 2025-01-01T00:00:00.000Z\nPreferred-Languages: fr, en\nCanonical: https://blacklanternsecurity.notreal/.well-known/security.txt\nPolicy: https://example.com/cert\nHiring: https://www.careers.example.com\n-----BEGIN PGP SIGNATURE-----\n\nSIGNATURE\n\n-----END PGP SIGNATURE-----",
        )

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.notreal": {
                    "A": ["127.0.0.11"],
                },
            }
        )

    def check(self, module_test, events):
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "joe.smith@blacklanternsecurity.notreal" for e in events
        ), "Failed to detect email address"
        assert not any(
            e.type == "URL_UNVERIFIED" and e.data == "https://blacklanternsecurity.notreal/.well-known/security.txt"
            for e in events
        ), "Failed to filter Canonical URL to self"
        assert not any(str(e.data) == "vdp@example.com" for e in events)


class TestSecurityTxtEmailsFalse(TestSecurityTxt):
    config_overrides = {
        "scope": {"report_distance": 1},
        "modules": {"securitytxt": {"emails": False}},
    }

    def check(self, module_test, events):
        assert not any(e.type == "EMAIL_ADDRESS" for e in events), "Detected email address when emails=False"
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://vdp.example.com/" for e in events
        ), "Failed to detect URL"
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://example.com/cert" for e in events
        ), "Failed to detect URL"
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://www.careers.example.com/" for e in events
        ), "Failed to detect URL"
