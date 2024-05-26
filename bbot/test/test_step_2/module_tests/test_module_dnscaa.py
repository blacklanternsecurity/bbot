from .base import ModuleTestBase


class TestDNSCAA(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]

    async def setup_after_prep(self, module_test):
        old_resolve_fn = module_test.scan.helpers.dns.resolve_raw

        async def resolve_raw(query, **kwargs):
            if query == "blacklanternsecurity.notreal" and kwargs.get("type", "").upper() == "CAA":
                return (
                    (
                        ("CAA", ['0 iodef "https://caa.blacklanternsecurity.notreal"']),
                        ("CAA", ['0 iodef "mailto:caa@blacklanternsecurity.notreal"']),
                    ),
                    (),
                )
            return await old_resolve_fn(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolve_raw", resolve_raw)

    def check(self, module_test, events):
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://caa.blacklanternsecurity.notreal/" for e in events
        ), "Failed to detect URL"
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "caa@blacklanternsecurity.notreal" for e in events
        ), "Failed to detect email address"
