from .base import ModuleTestBase


class TestDigitorus(ModuleTestBase):
    web_response = """<a href="/b8198b95b449ef633d3b671fdd5e5096a81bbc161afb07fa50d29edaac33bf88/asdf.blacklanternsecurity.com" title="Show the certificate for www.blacklanternsecurity.com">www.blacklanternsecurity.com</a><br>
<a href="/d92f154de36b1c3ea253a60a41c1a30e148e8964f92e10df4789692860ea80cb/zzzz.blacklanternsecurity.com" title="Show the certificate for chat.blacklanternsecurity.com">chat.blacklanternsecurity.com</a><br>
<a href="/e8b44651bd01af5d077045c2792c6038f0bf3d26684bf2170546d9affed4bf52/zzzz.blacklanternsecurity.com" title="Show the certificate for www.blacklanternsecurity.com">www.blacklanternsecurity.com</a><br>
<a href="/faef21c8c799d9ee1867ab6028ff33ade4d03c39277e65c9abe23e3633a10496/asdf.blacklanternsecurity.com" title="Show the certificate for tasks.blacklanternsecurity.com">tasks.blacklanternsecurity.com</a><br>
<a href="/ff1075573cc59a60073e968e61728a30b66974c234a9feeb07d695dfd3391512/asdf.blacklanternsecurity.com" title="Show the certificate for gitlab.blacklanternsecurity.com">gitlab.blacklanternsecurity.com</a><br>
"""

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://certificatedetails.com/blacklanternsecurity.com",
            text=self.web_response,
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
