from .base import ModuleTestBase


class TestGitlab_Com(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["gitlab_com", "httpx", "social", "excavate"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data("<a href='https://gitlab.org/veilidgroup'/>")
        module_test.httpx_mock.add_response(
            url="https://gitlab.org/api/v4/groups/veilidgroup/projects?simple=true",
            json=[
                {
                    "id": 55490429,
                    "description": None,
                    "name": "Veilid",
                    "name_with_namespace": "Veilid / Veilid",
                    "path": "veilid",
                    "path_with_namespace": "veilidgroup/veilid",
                    "created_at": "2024-03-03T05:22:53.169Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@gitlab.org:veilid/veilid.git",
                    "http_url_to_repo": "https://gitlab.org/veilidgroup/veilid.git",
                    "web_url": "https://gitlab.org/veilidgroup/veilid",
                    "readme_url": "https://gitlab.org/veilidgroup/veilid/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 0,
                    "last_activity_at": "2024-03-03T05:22:53.097Z",
                    "namespace": {
                        "id": 66882294,
                        "name": "veilidgroup",
                        "path": "veilidgroup",
                        "kind": "group",
                        "full_path": "veilidgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/66882294/signal-2023-07-04-192426_003.jpeg",
                        "web_url": "https://gitlab.org/groups/veilidgroup",
                    },
                },
            ],
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "gitlab"
                and e.data["profile_name"] == "veilidgroup"
                and e.data["url"] == "https://gitlab.org/veilidgroup"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://gitlab.org/veilidgroup/veilid"
                and str(e.module) == "gitlab_com"
            ]
        )
