from .base import ModuleTestBase


class TestAzure_Tenant(ModuleTestBase):
    tenant_response = {
        "tenant_id": "cc74fc12-4142-400e-a653-f98bdeadbeef",
        "tenant_name": "blacklanternsecurity",
        "domain": "blacklanternsecurity.com",
        "email_domains": [
            "blacklanternsecurity.com",
            "blacklanternsecurity.onmicrosoft.com",
            "blsgvt.com",
            "o365.blacklanternsecurity.com",
        ],
    }

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://azmap.dev/api/tenant?domain=blacklanternsecurity.com&extract=true",
            json=self.tenant_response,
        )

    def check(self, module_test, events):
        assert any(
            e.type.startswith("DNS_NAME")
            and e.data == "blacklanternsecurity.onmicrosoft.com"
            and "affiliate" in e.tags
            for e in events
        )
        assert any(
            e.type == "AZURE_TENANT"
            and e.data["tenant-id"] == "cc74fc12-4142-400e-a653-f98bdeadbeef"
            and "blacklanternsecurity.onmicrosoft.com" in e.data["domains"]
            and "blacklanternsecurity" in e.data["tenant-names"]
            for e in events
        )
