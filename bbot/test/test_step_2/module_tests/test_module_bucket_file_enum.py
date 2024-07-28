from .base import ModuleTestBase


class TestBucket_File_Enum(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["bucket_file_enum", "filedownload", "httpx", "excavate", "cloudcheck"]
    config_overrides = {"scope": {"report_distance": 5}}

    open_bucket_url = "https://testbucket.s3.amazonaws.com/"
    open_bucket_body = """<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>testbucket</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>index.html</Key><LastModified>2023-05-22T23:04:38.000Z</LastModified><ETag>&quot;4a2d2d114f3abf90f8bd127c1f25095a&quot;</ETag><Size>5</Size><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>test.pdf</Key><LastModified>2022-04-30T21:13:40.000Z</LastModified><ETag>&quot;723b0018c2f5a7ef06a34f84f6fa97e4&quot;</ETag><Size>388901</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"""

    pdf_data = """%PDF-1.
1 0 obj<</Pages 2 0 R>>endobj
2 0 obj<</Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Parent 2 0 R>>endobj
trailer <</Root 1 0 R>>"""

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(f'<a href="{self.open_bucket_url}"/>')
        module_test.httpx_mock.add_response(
            url=self.open_bucket_url,
            text=self.open_bucket_body,
        )
        module_test.httpx_mock.add_response(
            url=f"{self.open_bucket_url}test.pdf",
            text=self.pdf_data,
            headers={"Content-Type": "application/pdf"},
        )
        module_test.httpx_mock.add_response(
            url=f"{self.open_bucket_url}test.css",
            text="",
        )

    def check(self, module_test, events):
        download_dir = module_test.scan.home / "filedownload"
        files = list(download_dir.glob("*.pdf"))
        assert any(e.type == "URL_UNVERIFIED" and e.data.endswith("test.pdf") for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and e.data.endswith("test.css") for e in events)
        assert any(f.name.endswith("test.pdf") for f in files), "Failed to download PDF file from open bucket"
        assert not any(f.name.endswith("test.css") for f in files), "Unwanted CSS file was downloaded"
