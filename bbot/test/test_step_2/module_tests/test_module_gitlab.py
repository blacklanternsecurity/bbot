from .base import ModuleTestBase


class TestGitlab(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["gitlab", "httpx"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(headers={"X-Gitlab-Meta": "asdf"})
        module_test.httpserver.expect_request("/api/v4/projects", query_string="simple=true").respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "bbot",
                    "name_with_namespace": "bbot / BBOT",
                    "path": "bbot",
                    "path_with_namespace": "bbotgroup/bbot",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@127.0.0.1:8888:bbot/bbot.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/bbotgroup/bbot.git",
                    "web_url": "http://127.0.0.1:8888/bbotgroup/bbot",
                    "readme_url": "http://127.0.0.1:8888/bbotgroup/bbot/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "bbotgroup",
                        "path": "bbotgroup",
                        "kind": "group",
                        "full_path": "bbotgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/bbotgroup",
                    },
                },
            ],
        )
        module_test.httpserver.expect_request("/api/v4/groups", query_string="simple=true").respond_with_json(
            [
                {
                    "id": 9,
                    "web_url": "http://127.0.0.1:8888/groups/bbotgroup",
                    "name": "bbotgroup",
                    "path": "bbotgroup",
                    "description": "OSINT automation for hackers.",
                    "visibility": "public",
                    "share_with_group_lock": False,
                    "require_two_factor_authentication": False,
                    "two_factor_grace_period": 48,
                    "project_creation_level": "developer",
                    "auto_devops_enabled": None,
                    "subgroup_creation_level": "owner",
                    "emails_disabled": False,
                    "emails_enabled": True,
                    "mentions_disabled": None,
                    "lfs_enabled": True,
                    "math_rendering_limits_enabled": True,
                    "lock_math_rendering_limits_enabled": False,
                    "default_branch_protection": 2,
                    "default_branch_protection_defaults": {
                        "allowed_to_push": [{"access_level": 30}],
                        "allow_force_push": True,
                        "allowed_to_merge": [{"access_level": 30}],
                    },
                    "avatar_url": "http://127.0.0.1:8888/uploads/-/system/group/avatar/9/index.png",
                    "request_access_enabled": False,
                    "full_name": "bbotgroup",
                    "full_path": "bbotgroup",
                    "created_at": "2018-05-15T14:31:12.027Z",
                    "parent_id": None,
                    "organization_id": 1,
                    "shared_runners_setting": "enabled",
                    "ldap_cn": None,
                    "ldap_access": None,
                    "marked_for_deletion_on": None,
                    "wiki_access_level": "enabled",
                }
            ]
        )
        module_test.httpserver.expect_request(
            "/api/v4/groups/bbotgroup/projects", query_string="simple=true"
        ).respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "bbot2",
                    "name_with_namespace": "bbotgroup / bbot2",
                    "path": "bbot2",
                    "path_with_namespace": "bbotgroup/bbot2",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@blacklanternsecurity.com:bbotgroup/bbot2.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/bbotgroup/bbot2.git",
                    "web_url": "http://127.0.0.1:8888/bbotgroup/bbot2",
                    "readme_url": "http://127.0.0.1:8888/bbotgroup/bbot2/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "bbotgroup",
                        "path": "bbotgroup",
                        "kind": "group",
                        "full_path": "bbotgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/bbotgroup",
                    },
                },
            ]
        )
        module_test.httpserver.expect_request(
            "/api/v4/users/bbotgroup/projects", query_string="simple=true"
        ).respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "bbot3",
                    "name_with_namespace": "bbotgroup / bbot3",
                    "path": "bbot3",
                    "path_with_namespace": "bbotgroup/bbot3",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@blacklanternsecurity.com:bbotgroup/bbot3.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/bbotgroup/bbot3.git",
                    "web_url": "http://127.0.0.1:8888/bbotgroup/bbot3",
                    "readme_url": "http://127.0.0.1:8888/bbotgroup/bbot3/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "bbotgroup",
                        "path": "bbotgroup",
                        "kind": "group",
                        "full_path": "bbotgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/bbotgroup",
                    },
                },
            ]
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY"
                and e.data["technology"] == "GitLab"
                and e.data["url"] == "http://127.0.0.1:8888/"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "gitlab"
                and e.data["profile_name"] == "bbotgroup"
                and e.data["url"] == "http://127.0.0.1:8888/bbotgroup"
                and str(e.module) == "gitlab"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/bbotgroup/bbot"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/bbotgroup/bbot2"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/bbotgroup/bbot3"
            ]
        )


class TestGitlabDotOrg(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["gitlab", "httpx", "social", "excavate"]

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
                and str(e.module) == "gitlab"
            ]
        )
