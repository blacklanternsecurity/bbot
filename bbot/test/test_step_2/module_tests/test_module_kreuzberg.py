import base64
from pathlib import Path
from .base import ModuleTestBase

from ...bbot_fixtures import *


class TestKreuzberg(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["kreuzberg", "filedownload", "httpx", "excavate", "speculate"]
    config_overrides = {
        "web": {
            "spider_distance": 2,
            "spider_depth": 2,
        },
        "modules": {
            "filedownload": {
                "output_folder": bbot_test_dir / "filedownload",
            },
        },
    }

    pdf_data = base64.b64decode(
        "JVBERi0xLjMKJe+/ve+/ve+/ve+/vSBSZXBvcnRMYWIgR2VuZXJhdGVkIFBERiBkb2N1bWVudCBodHRwOi8vd3d3LnJlcG9ydGxhYi5jb20KMSAwIG9iago8PAovRjEgMiAwIFIKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL0Jhc2VGb250IC9IZWx2ZXRpY2EgL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcgL05hbWUgL0YxIC9TdWJ0eXBlIC9UeXBlMSAvVHlwZSAvRm9udAo+PgplbmRvYmoKMyAwIG9iago8PAovQ29udGVudHMgNyAwIFIgL01lZGlhQm94IFsgMCAwIDU5NS4yNzU2IDg0MS44ODk4IF0gL1BhcmVudCA2IDAgUiAvUmVzb3VyY2VzIDw8Ci9Gb250IDEgMCBSIC9Qcm9jU2V0IFsgL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSSBdCj4+IC9Sb3RhdGUgMCAvVHJhbnMgPDwKCj4+IAogIC9UeXBlIC9QYWdlCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9QYWdlTW9kZSAvVXNlTm9uZSAvUGFnZXMgNiAwIFIgL1R5cGUgL0NhdGFsb2cKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL0F1dGhvciAoYW5vbnltb3VzKSAvQ3JlYXRpb25EYXRlIChEOjIwMjQwNjAzMTg1ODE2KzAwJzAwJykgL0NyZWF0b3IgKFJlcG9ydExhYiBQREYgTGlicmFyeSAtIHd3dy5yZXBvcnRsYWIuY29tKSAvS2V5d29yZHMgKCkgL01vZERhdGUgKEQ6MjAyNDA2MDMxODU4MTYrMDAnMDAnKSAvUHJvZHVjZXIgKFJlcG9ydExhYiBQREYgTGlicmFyeSAtIHd3dy5yZXBvcnRsYWIuY29tKSAKICAvU3ViamVjdCAodW5zcGVjaWZpZWQpIC9UaXRsZSAodW50aXRsZWQpIC9UcmFwcGVkIC9GYWxzZQo+PgplbmRvYmoKNiAwIG9iago8PAovQ291bnQgMSAvS2lkcyBbIDMgMCBSIF0gL1R5cGUgL1BhZ2VzCj4+CmVuZG9iago3IDAgb2JqCjw8Ci9GaWx0ZXIgWyAvQVNDSUk4NURlY29kZSAvRmxhdGVEZWNvZGUgXSAvTGVuZ3RoIDEwNwo+PgpzdHJlYW0KR2FwUWgwRT1GLDBVXEgzVFxwTllUXlFLaz90Yz5JUCw7VyNVMV4yM2loUEVNXz9DVzRLSVNpOTBNakdeMixGUyM8UkM1K2MsbilaOyRiSyRiIjVJWzwhXlREI2dpXSY9NVgsWzVAWUBWfj5lbmRzdHJlYW0KZW5kb2JqCnhyZWYKMCA4CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDA3MyAwMDAwMCBuIAowMDAwMDAwMTA0IDAwMDAwIG4gCjAwMDAwMDAyMTEgMDAwMDAgbiAKMDAwMDAwMDQxNCAwMDAwMCBuIAowMDAwMDAwNDgyIDAwMDAwIG4gCjAwMDAwMDA3NzggMDAwMDAgbiAKMDAwMDAwMDgzNyAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9JRCAKWzw4MGQ5ZjViOTY0ZmM5OTI4NDUwMWRlYjdhNmE2MzdmNz48ODBkOWY1Yjk2NGZjOTkyODQ1MDFkZWI3YTZhNjM3Zjc+XQolIFJlcG9ydExhYiBnZW5lcmF0ZWQgUERGIGRvY3VtZW50IC0tIGRpZ2VzdCAoaHR0cDovL3d3dy5yZXBvcnRsYWIuY29tKQoKL0luZm8gNSAwIFIKL1Jvb3QgNCAwIFIKL1NpemUgOAo+PgpzdGFydHhyZWYKMTAzNAolJUVPRg=="
    )

    docx_data = base64.b64decode(
        "UEsDBBQAAAAAAFitWVzXeYTquAEAALgBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbDw/eG1sIHZl"
        "cnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz4KPFR5cGVzIHht"
        "bG5zPSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvcGFja2FnZS8yMDA2L2NvbnRl"
        "bnQtdHlwZXMiPgogIDxEZWZhdWx0IEV4dGVuc2lvbj0icmVscyIgQ29udGVudFR5cGU9ImFwcGxp"
        "Y2F0aW9uL3ZuZC5vcGVueG1sZm9ybWF0cy1wYWNrYWdlLnJlbGF0aW9uc2hpcHMreG1sIi8+CiAg"
        "PERlZmF1bHQgRXh0ZW5zaW9uPSJ4bWwiIENvbnRlbnRUeXBlPSJhcHBsaWNhdGlvbi94bWwiLz4K"
        "ICA8T3ZlcnJpZGUgUGFydE5hbWU9Ii93b3JkL2RvY3VtZW50LnhtbCIgQ29udGVudFR5cGU9ImFw"
        "cGxpY2F0aW9uL3ZuZC5vcGVueG1sZm9ybWF0cy1vZmZpY2Vkb2N1bWVudC53b3JkcHJvY2Vzc2lu"
        "Z21sLmRvY3VtZW50Lm1haW4reG1sIi8+CjwvVHlwZXM+UEsDBBQAAAAAAFitWVwgG4bqLgEAAC4B"
        "AAALAAAAX3JlbHMvLnJlbHM8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJVVEYtOCIgc3Rh"
        "bmRhbG9uZT0ieWVzIj8+CjxSZWxhdGlvbnNoaXBzIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5vcGVu"
        "eG1sZm9ybWF0cy5vcmcvcGFja2FnZS8yMDA2L3JlbGF0aW9uc2hpcHMiPgogIDxSZWxhdGlvbnNo"
        "aXAgSWQ9InJJZDEiIFR5cGU9Imh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9vZmZp"
        "Y2VEb2N1bWVudC8yMDA2L3JlbGF0aW9uc2hpcHMvb2ZmaWNlRG9jdW1lbnQiIFRhcmdldD0id29y"
        "ZC9kb2N1bWVudC54bWwiLz4KPC9SZWxhdGlvbnNoaXBzPlBLAwQUAAAAAABYrVlcNNIntwABAAAA"
        "AQAAEQAAAHdvcmQvZG9jdW1lbnQueG1sPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRG"
        "LTgiIHN0YW5kYWxvbmU9InllcyI/Pgo8dzpkb2N1bWVudCB4bWxuczp3PSJodHRwOi8vc2NoZW1h"
        "cy5vcGVueG1sZm9ybWF0cy5vcmcvd29yZHByb2Nlc3NpbmdtbC8yMDA2L21haW4iPgogIDx3OmJv"
        "ZHk+CiAgICA8dzpwPgogICAgICA8dzpyPgogICAgICAgIDx3OnQ+SGVsbG8sIFdvcmxkISE8L3c6"
        "dD4KICAgICAgPC93OnI+CiAgICA8L3c6cD4KICA8L3c6Ym9keT4KPC93OmRvY3VtZW50PlBLAQIU"
        "AxQAAAAAAFitWVzXeYTquAEAALgBAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10u"
        "eG1sUEsBAhQDFAAAAAAAWK1ZXCAbhuouAQAALgEAAAsAAAAAAAAAAAAAAIAB6QEAAF9yZWxzLy5y"
        "ZWxzUEsBAhQDFAAAAAAAWK1ZXDTSJ7cAAQAAAAEAABEAAAAAAAAAAAAAAIABQAMAAHdvcmQvZG9j"
        "dW1lbnQueG1sUEsFBgAAAAADAAMAuQAAAG8EAAAAAA=="
    )

    expected_result_pdf = "Hello, World!"
    expected_result_docx = "Hello, World!!"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            {"uri": "/"},
            {"response_data": '<a href="/Test_PDF"/><a href="/Test_DOCX"/>'},
        )
        module_test.set_expect_requests(
            {"uri": "/Test_PDF"},
            {"response_data": self.pdf_data, "headers": {"Content-Type": "application/pdf"}},
        )
        module_test.set_expect_requests(
            {"uri": "/Test_DOCX"},
            {
                "response_data": self.docx_data,
                "headers": {"Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            },
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        assert 2 == len(filesystem_events), filesystem_events
        for filesystem_event in filesystem_events:
            file = Path(filesystem_event.data["path"])
            assert file.is_file(), "Destination file doesn't exist"
            assert open(file, "rb").read() == self.pdf_data or open(file, "rb").read() == self.docx_data, (
                f"File at {file} does not contain the correct content"
            )
        raw_text_events = [e for e in events if e.type == "RAW_TEXT"]
        assert 2 == len(raw_text_events), "Failed to emit RAW_TEXT event"
        for raw_text_event in raw_text_events:
            assert raw_text_event.data in [
                self.expected_result_pdf,
                self.expected_result_docx,
            ], f"Text extracted from {raw_text_event.data['path']} is incorrect, got {raw_text_event.data}"
