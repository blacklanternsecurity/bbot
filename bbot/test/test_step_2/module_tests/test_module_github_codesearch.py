from .base import ModuleTestBase


class TestGithub_Codesearch(ModuleTestBase):
    config_overrides = {
        "modules": {"github_codesearch": {"api_key": "asdf", "limit": 1}},
        "omit_event_types": [],
        "scope": {"report_distance": 2},
    }
    modules_overrides = ["github_codesearch", "httpx", "secretsdb"]

    github_file_endpoint = (
        "/projectdiscovery/nuclei/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go"
    )
    github_file_url = f"http://127.0.0.1:8888{github_file_endpoint}"
    github_file_content = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

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
        assert [
            e for e in events if e.type == "FINDING" and str(e.module) == "secretsdb"
        ], "Failed to find secret in repo file"
