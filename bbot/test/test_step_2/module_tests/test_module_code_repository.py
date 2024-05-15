from .base import ModuleTestBase


class TestCodeRepository(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "excavate", "code_repository"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": """
            <html>
                <a href="https://github.com/blacklanternsecurity/bbot"/>
                <a href="https://gitlab.com/blacklanternsecurity/bbot"/>
                <a href="https://gitlab.org/blacklanternsecurity/bbot"/>
                <a href="https://hub.docker.com/r/blacklanternsecurity/bbot"/>
            </html>
            """
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert 4 == len([e for e in events if e.type == "CODE_REPOSITORY"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://github.com/blacklanternsecurity/bbot"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://gitlab.com/blacklanternsecurity/bbot"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://gitlab.org/blacklanternsecurity/bbot"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "docker" in e.tags
                and e.data["url"] == "https://hub.docker.com/r/blacklanternsecurity/bbot"
            ]
        )
