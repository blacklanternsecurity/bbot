from .base import ModuleTestBase


class TestRiddler(ModuleTestBase):
    web_body = """<th scope="row ">12</th>
<td>asdf.blacklanternsecurity.com</td>
<td><a href="/sameip/asdf.blacklanternsecurity.com.?t=cname#result" target="_blank" title="asdf.blacklanternsecurity.com. same ip website">asdf.blacklanternsecurity.com.</a>"""

    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        module_test.httpx_mock.add_response(
            url=f"https://riddler.io/search/exportcsv?q=pld:blacklanternsecurity.com", text=self.web_body
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
