from .base import ModuleTestBase


class TestNeo4j(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        # install py2neo
        deps_pip = module_test.preloaded["neo4j"]["deps"]["pip"]
        await module_test.scan.helpers.depsinstaller.pip_install(deps_pip)

        class MockGraph:
            def __init__(self, *args, **kwargs):
                self.used = False

            def merge(self, *args, **kwargs):
                self.used = True

        module_test.monkeypatch.setattr("py2neo.Graph", MockGraph)

    def check(self, module_test, events):
        assert module_test.scan.modules["neo4j"].neo4j.graph.used == True
