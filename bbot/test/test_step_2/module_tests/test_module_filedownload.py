from .base import ModuleTestBase


class TestFileDownload(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["filedownload", "httpx", "excavate", "speculate"]
    config_overrides = {"web_spider_distance": 2, "web_spider_depth": 2}

    pdf_data = """%PDF-1.
1 0 obj<</Pages 2 0 R>>endobj
2 0 obj<</Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Parent 2 0 R>>endobj
trailer <</Root 1 0 R>>"""

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://raw.githubusercontent.com/jshttp/mime-db/master/db.json",
            json={
                "application/pdf": {"source": "iana", "compressible": False, "extensions": ["pdf"]},
            },
        )

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
        download_dir = module_test.scan.home / "filedownload"

        # text file
        text_files = list(download_dir.glob("*test-file.txt"))
        assert len(text_files) == 1, f"No text file found at {download_dir}"
        file = text_files[0]
        assert file.is_file(), f"File not found at {file}"
        assert open(file).read() == "juicy stuff", f"File at {file} does not contain the correct content"

        # PDF file (no extension)
        pdf_files = list(download_dir.glob("*test-pdf.pdf"))
        assert len(pdf_files) == 1, f"No PDF file found at {download_dir}"
        file = pdf_files[0]
        assert file.is_file(), f"File not found at {file}"
        assert open(file).read() == self.pdf_data, f"File at {file} does not contain the correct content"

        # we don't want html files
        html_files = list(download_dir.glob("*.html"))
        assert len(html_files) == 0, "HTML files were erroneously downloaded"
