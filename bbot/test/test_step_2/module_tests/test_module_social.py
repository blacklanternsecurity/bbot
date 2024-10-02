from .base import ModuleTestBase


class TestSocial(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "excavate", "social"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": """
            <html>
                <a href="https://discord.gg/asdf"/><a href="https://github.com/blacklanternsecurity/bbot"/>
                <a href="https://hub.docker.com/r/blacklanternsecurity"/>
                <a href="https://hub.docker.com/r/blacklanternsecurity/bbot"/>
                <a href="https://hub.docker.com/r/blacklanternSECURITY/bbot"/>
                <a href="https://www.postman.com/blacklanternsecurity/bbot"/>
            </html>
            """
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert 4 == len([e for e in events if e.type == "SOCIAL"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL" and e.data["platform"] == "discord" and e.data["profile_name"] == "asdf"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "docker"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "postman"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        )
