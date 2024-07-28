from pathlib import Path
from .base import ModuleTestBase


class TestFileDownload(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["filedownload", "httpx", "excavate", "speculate"]
    config_overrides = {"web": {"spider_distance": 2, "spider_depth": 2}}

    pdf_data = """%PDF-1.
1 0 obj<</Pages 2 0 R>>endobj
2 0 obj<</Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Parent 2 0 R>>endobj
trailer <</Root 1 0 R>>"""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(
                response_data='<a href="/Test_File.txt"/><a href="/Test_PDF"/><a href="/test.html"/><a href="/test2"/>'
            ),
        )
        module_test.set_expect_requests(
            dict(uri="/Test_File.txt"),
            dict(
                response_data="juicy stuff",
            ),
        )
        module_test.set_expect_requests(
            dict(uri="/Test_PDF"),
            dict(response_data=self.pdf_data, headers={"Content-Type": "application/pdf"}),
        )
        module_test.set_expect_requests(
            dict(uri="/test.html"),
            dict(response_data="<!DOCTYPE html>", headers={"Content-Type": "text/html"}),
        )
        module_test.set_expect_requests(
            dict(uri="/test2"),
            dict(response_data="<!DOCTYPE html>", headers={"Content-Type": "text/html"}),
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        download_dir = module_test.scan.home / "filedownload"

        # text file
        text_file_event = [e for e in filesystem_events if "test-file.txt" in e.data["path"]]
        assert 1 == len(text_file_event), f"No text file found at {download_dir}"
        file = Path(text_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        assert open(file).read() == "juicy stuff", f"File at {file} does not contain the correct content"

        # PDF file (no extension)
        pdf_file_event = [e for e in filesystem_events if "test-pdf.pdf" in e.data["path"]]
        assert 1 == len(pdf_file_event), f"No PDF file found at {download_dir}"
        file = Path(pdf_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        assert open(file).read() == self.pdf_data, f"File at {file} does not contain the correct content"

        # we don't want html files
        html_files = list(download_dir.glob("*.html"))
        assert len(html_files) == 0, "HTML files were erroneously downloaded"
