from .base import ModuleTestBase


class TestNeo4j(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        # install neo4j
        deps_pip = module_test.preloaded["neo4j"]["deps"]["pip"]
        await module_test.scan.helpers.depsinstaller.pip_install(deps_pip)

        self.neo4j_used = False

        class MockResult:
            async def single(s):
                self.neo4j_used = True
                return {"id(_)": 1}

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
        assert self.neo4j_used == True
