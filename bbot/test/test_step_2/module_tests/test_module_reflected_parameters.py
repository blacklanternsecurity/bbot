from .base import ModuleTestBase
from werkzeug.wrappers import Response
import re

from .test_module_paramminer_getparams import TestParamminer_Getparams


class TestReflected_parameters_fromexcavate(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "reflected_parameters", "excavate"]

    def request_handler(self, request):
        normal_block = f'<html><a href="/?reflected=foo">foo</a></html>'
        qs = str(request.query_string.decode())
        if "reflected=" in qs:
            value = qs.split("=")[1]
            if "&" in value:
                value = value.split("&")[0]
            reflected_block = f'<html><a href="/?reflected={value}"></a></html>'
            return Response(reflected_block, status=200)
        else:
            return Response(normal_block, status=200)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == "GET Parameter value reflected in response body. Name: [reflected] Source Module: [excavate] Original Value: [foo]"
            for e in events
        )


class TestReflected_parameters_fromparamminer(TestParamminer_Getparams):
    modules_overrides = ["httpx", "paramminer_getparams", "reflected_parameters"]

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "GET Parameter value reflected in response body. Name: [id] Source Module: [paramminer_getparams]"
            in e.data["description"]
            for e in events
        )
