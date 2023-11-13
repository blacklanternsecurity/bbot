from .base import ModuleTestBase


class TestSubdomain_Hijack(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "excavate", "subdomain_hijack"]

    async def setup_after_prep(self, module_test):
        fingerprints = module_test.module.fingerprints
        assert fingerprints, "No subdomain hijacking fingerprints available"
        fingerprint = next(iter(fingerprints))
        rand_string = module_test.scan.helpers.rand_string(length=15, digits=False)
        self.rand_subdomain = f"{rand_string}.{next(iter(fingerprint.domains))}"
        respond_args = {"response_data": f'<a src="http://{self.rand_subdomain}"/>'}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            event.type == "FINDING"
            and event.data["description"].startswith("Hijackable Subdomain")
            and self.rand_subdomain in event.data["description"]
            and event.data["host"] == self.rand_subdomain
            for event in events
        ), f"No hijackable subdomains in {events}"
