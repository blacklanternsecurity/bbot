import json
from .base import ModuleTestBase


class TestHTTPX(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/url", "127.0.0.1:8888"]

    async def setup_after_prep(self, module_test):
        request_args = dict(uri="/", headers={"test": "header"})
        respond_args = dict(response_data=json.dumps({"open": "port"}))
        module_test.set_expect_requests(request_args, respond_args)
        request_args = dict(uri="/url", headers={"test": "header"})
        respond_args = dict(response_data=json.dumps({"url": "url"}))
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        url = False
        open_port = False
        for e in events:
            if e.type == "HTTP_RESPONSE":
                j = json.loads(e.data["body"])
                if e.data["path"] == "/":
                    if j.get("open", "") == "port":
                        open_port = True
                elif e.data["path"] == "/url":
                    if j.get("url", "") == "url":
                        url = True
        assert url, "Failed to visit target URL"
        assert open_port, "Failed to visit target OPEN_TCP_PORT"
