from .base import ModuleTestBase


class TestGraphQLIntrospectionNon200(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["graphql_introspection"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/"},
            respond_args={"response_data": "ok"},
        )

    def check(self, module_test, events):
        assert all(e.type != "FINDING" for e in events), "should have raised 0 events"


class TestGraphQLIntrospection(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["graphql_introspection"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/"},
            respond_args={
                "response_data": """{"data": {"__schema": {"types": ["dummy"]}}}""",
            },
        )

    def check(self, module_test, events):
        finding = [e for e in events if e.type == "FINDING"]
        assert finding, "should have raised 1 FINDING event"
        assert finding[0].data["url"] == "http://127.0.0.1:8888/"
        assert finding[0].data["description"] == "GraphQL schema"
