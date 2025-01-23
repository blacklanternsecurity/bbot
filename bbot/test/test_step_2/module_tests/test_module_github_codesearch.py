from .base import ModuleTestBase


class TestGithub_Codesearch(ModuleTestBase):
    config_overrides = {
        "modules": {
            "github_codesearch": {"api_key": "asdf", "limit": 1},
            "trufflehog": {"only_verified": False},
        },
        "omit_event_types": [],
        "scope": {"report_distance": 2},
    }
    modules_overrides = ["github_codesearch", "httpx", "trufflehog"]

    github_file_endpoint = (
        "/projectdiscovery/nuclei/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go"
    )
    github_file_url = f"http://127.0.0.1:8888{github_file_endpoint}"
    github_file_content = """-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOBY2pd9PSQvuxqu
WXFNVgILTWuUc721Wc2sFNvp4beowhUe1lfxaq5ZfCJcz7z4QsqFhOeks69O9UIb
oiOTDocPDog9PHO8yZXopHm0StFZvSjjKSNuFvy/WopPTGpxUZ5boCaF1CXumY7W
FL+jIap5faimLL9prIwaQKBwv80lAgMBAAECgYEAxvpHtgCgD849tqZYMgOTevCn
U/kwxltoMOClB39icNA+gxj8prc6FTTMwnVq0oGmS5UskX8k1yHCqUV1AvRU9o+q
I8L8a3F3TQKQieI/YjiUNK8A87bKkaiN65ooOnhT+I3ZjZMPR5YEyycimMp22jsv
LyX/35J/wf1rNiBs/YECQQDvtxgmMhE+PeajXqw1w2C3Jds27hI3RPDnamEyWr/L
KkSplbKTF6FuFDYOFdJNPrfxm1tx2MZ2cBfs+h/GnCJVAkEA75Z9w7q8obbqGBHW
9bpuFvLjW7bbqO7HBuXYX9zQcZL6GSArFP0ba5lhgH1qsVQfxVWVyiV9/chme7xc
ljfvkQJBAJ7MpSPQcRnRefNp6R0ok+5gFqt55PlWI1y6XS81bO7Szm+laooE0n0Q
yIpmLE3dqY9VgquVlkupkD/9poU0s40CQD118ZVAVht1/N9n1Cj9RjiE3mYspnTT
rCLM25Db6Gz6M0Y2xlaAB4S2uBhqE/Chj/TjW6WbsJJl0kRzsZynhMECQFYKiM1C
T4LB26ynW00VE8z4tEWSoYt4/Vn/5wFhalVjzoSJ8Hm2qZiObRYLQ1m0X4KnkShk
Gnl54dJHT+EhlfY=
-----END PRIVATE KEY-----"""

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": self.github_file_endpoint}
        respond_args = {"response_data": self.github_file_content}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        module_test.httpx_mock.add_response(url="https://api.github.com/zen")
        module_test.httpx_mock.add_response(
            url="https://api.github.com/search/code?per_page=100&type=Code&q=blacklanternsecurity.com&page=1",
            json={
                "total_count": 214,
                "incomplete_results": False,
                "items": [
                    {
                        "html_url": "https://github.com/projectdiscovery/nuclei/blob/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go",
                        "repository": {
                            "html_url": "https://github.com/projectdiscovery/nuclei",
                        },
                    },
                    {
                        "html_url": "https://github.com/projectdiscovery/nuclei/blob/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go2",
                        "repository": {
                            "html_url": "https://github.com/projectdiscovery/nuclei",
                        },
                    },
                    {
                        "html_url": "https://github.com/projectdiscovery/nuclei/blob/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go3",
                        "repository": {
                            "html_url": "https://github.com/projectdiscovery/nuclei",
                        },
                    },
                ],
            },
        )

    async def setup_after_prep(self, module_test):
        module_test.module.github_raw_url = "http://127.0.0.1:8888/"

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.type == "URL_UNVERIFIED"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED" and e.data == self.github_file_url and e.scope_distance == 2
            ]
        ), "Failed to emit URL_UNVERIFIED"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://github.com/projectdiscovery/nuclei"
                and e.scope_distance == 1
            ]
        ), "Failed to emit CODE_REPOSITORY"
        assert 1 == len(
            [e for e in events if e.type == "URL" and e.data == self.github_file_url and e.scope_distance == 2]
        ), "Failed to visit URL"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HTTP_RESPONSE" and e.data["url"] == self.github_file_url and e.scope_distance == 2
            ]
        ), "Failed to visit URL"
        assert [e for e in events if e.type == "FINDING" and str(e.module) == "trufflehog"], (
            "Failed to find secret in repo file"
        )
