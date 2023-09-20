from .base import ModuleTestBase


class TestFileDownload(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["filedownload", "httpx", "excavate"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(dict(uri="/"), dict(response_data='<a href="/Test_File.txt"/>'))
        module_test.set_expect_requests(dict(uri="/Test_File.txt"), dict(response_data="juicy stuff"))

    def check(self, module_test, events):
        download_dir = module_test.scan.home / "filedownload"
        files = list(download_dir.glob("*_test-file.txt"))
        assert len(files) == 1, f"No file found at {download_dir}"
        file = files[0]
        assert file.is_file(), f"File not found at {file}"
        assert open(file).read() == "juicy stuff", f"File at {file} does not contain the correct content"
