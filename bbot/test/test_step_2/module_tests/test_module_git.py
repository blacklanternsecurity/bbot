from .base import ModuleTestBase


class TestGit(ModuleTestBase):
    targets = [
        "http://127.0.0.1:8888/",
        "http://127.0.0.1:8888/test/asdf",
        "http://127.0.0.1:8888/test2",
    ]

    modules_overrides = ["git", "httpx"]

    git_config = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true"""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"uri": "/.git/config"}, respond_args={"response_data": self.git_config}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/.git/config"}, respond_args={"response_data": self.git_config}
        )
        module_test.set_expect_requests(
            expect_args={"uri": "/test/asdf/.git/config"}, respond_args={"response_data": self.git_config}
        )
        module_test.set_expect_requests(expect_args={"uri": "/test2/.git/config"}, respond_args={"response_data": ""})

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "http://127.0.0.1:8888/.git/config" in e.data["description"] for e in events
        )
        assert any(
            e.type == "FINDING" and "http://127.0.0.1:8888/test/.git/config" in e.data["description"] for e in events
        )
        assert any(
            e.type == "FINDING" and "http://127.0.0.1:8888/test/asdf/.git/config" in e.data["description"]
            for e in events
        )
        assert not any(
            e.type == "FINDING" and "http://127.0.0.1:8888/test2/.git/config" in e.data["description"] for e in events
        )
