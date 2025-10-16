from .base import ModuleTestBase


class TestDNSDumpster(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://dnsdumpster.com",
            content=b"""<form data-form-id="mainform" class="mb-6" hx-post="https://api.dnsdumpster.com/htmld/" hx-target="#results" hx-headers='{"Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjAsImlhdCI6MTc1OTAxODczOCwiZXhwIjoxNzU5MDE5NjM4LCJkYXRhIjoiZmMxMDcwOTVjYmRjN2Y5YjU1ZWJiM2ZlZGViNWQ5Y2M5MWU1NmEzNGEwYzliNzM5ZjRlYzg2Mjk4MmM0ZDI5YSIsIm1lbWJlcl9zdGF0dXMiOiJmcmVlIn0.7NWBC6TFSaDZH-_VKqDoXqv3nH4a1k30NUxrijg1KqI"}'><div class="form-group">""",
        )
        module_test.httpx_mock.add_response(
            url="https://api.dnsdumpster.com/htmld/",
            content=b"asdf.blacklanternsecurity.com",
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
