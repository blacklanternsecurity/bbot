from .base import ModuleTestBase


class TestNeo4j(ModuleTestBase):
    config_overrides = {"modules": {"neo4j": {"uri": "bolt://127.0.0.1:11111"}}}

    async def setup_before_prep(self, module_test):
        # install neo4j
        deps_pip = module_test.preloaded["neo4j"]["deps"]["pip"]
        await module_test.scan.helpers.depsinstaller.pip_install(deps_pip)

        self.neo4j_used = False

        class MockResult:
            async def data(s):
                self.neo4j_used = True
                return [
                    {
                        "neo4j_id": "4:ee79a477-5f5b-445a-9def-7c051b2a533c:115",
                        "event_id": "DNS_NAME:c8fab50640cb87f8712d1998ecc78caf92b90f71",
                    }
                ]

        class MockSession:
            async def run(s, *args, **kwargs):
                return MockResult()

            async def close(self):
                pass

        class MockDriver:
            def __init__(self, *args, **kwargs):
                pass

            def session(self, *args, **kwargs):
                return MockSession()

            async def close(self):
                pass

        module_test.monkeypatch.setattr("neo4j.AsyncGraphDatabase.driver", MockDriver)

    def check(self, module_test, events):
        assert self.neo4j_used is True
