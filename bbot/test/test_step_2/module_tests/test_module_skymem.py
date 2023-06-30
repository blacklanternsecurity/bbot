from .base import ModuleTestBase


class TestSkymem(ModuleTestBase):
    targets = ["blacklanternsecurity.com"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/srch?q=blacklanternsecurity.com",
            text=page_1_body,
        )
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/domain/5679236812ad5b3f748a413d?p=2",
            text=page_2_body,
        )
        module_test.httpx_mock.add_response(
            url="https://www.skymem.info/domain/5679236812ad5b3f748a413d?p=3",
            text=page_3_body,
        )

    def check(self, module_test, events):
        assert any(e.data == "page1email@blacklanternsecurity.com" for e in events), "Failed to detect first email"
        assert any(e.data == "page2email@blacklanternsecurity.com" for e in events), "Failed to detect second email"
        assert any(e.data == "page3email@blacklanternsecurity.com" for e in events), "Failed to detect third email"


page_1_body = """
<a href="/srch?q=page1email@blacklanternsecurity.com">page1email@blacklanternsecurity.com</a>
<a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
<a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
"""

page_2_body = """
<a href="/srch?q=page2email@blacklanternsecurity.com">page2email@blacklanternsecurity.com</a>
<a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
<a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
"""

page_3_body = """
<a href="/srch?q=page3email@blacklanternsecurity.com">page3email@blacklanternsecurity.com</a>
<a href="/domain/5679236812ad5b3f748a413d?p=2"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
<a href="/domain/5679236812ad5b3f748a413d?p=3"><i class="fa fa-arrow-right fa-lg"></i> More emails for <strong>blacklanternsecurity.com </strong> ...</a>
"""
