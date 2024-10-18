from .base import ModuleTestBase


class TestGithub_Org(ModuleTestBase):
    config_overrides = {"modules": {"github_org": {"api_key": "asdf"}}}
    modules_overrides = ["github_org", "speculate"]

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns(
            {"blacklanternsecurity.com": {"A": ["127.0.0.99"]}, "github.com": {"A": ["127.0.0.99"]}}
        )

        module_test.httpx_mock.add_response(
            url="https://api.github.com/zen", match_headers={"Authorization": "token asdf"}
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/orgs/blacklanternsecurity",
            match_headers={"Authorization": "token asdf"},
            json={
                "login": "blacklanternsecurity",
                "id": 25311592,
                "node_id": "MDEyOk9yZ2FuaXphdGlvbjI1MzExNTky",
                "url": "https://api.github.com/orgs/blacklanternsecurity",
                "repos_url": "https://api.github.com/orgs/blacklanternsecurity/repos",
                "events_url": "https://api.github.com/orgs/blacklanternsecurity/events",
                "hooks_url": "https://api.github.com/orgs/blacklanternsecurity/hooks",
                "issues_url": "https://api.github.com/orgs/blacklanternsecurity/issues",
                "members_url": "https://api.github.com/orgs/blacklanternsecurity/members{/member}",
                "public_members_url": "https://api.github.com/orgs/blacklanternsecurity/public_members{/member}",
                "avatar_url": "https://avatars.githubusercontent.com/u/25311592?v=4",
                "description": "Security Organization",
                "name": "Black Lantern Security",
                "company": None,
                "blog": "www.blacklanternsecurity.com",
                "location": "Charleston, SC",
                "email": None,
                "twitter_username": None,
                "is_verified": False,
                "has_organization_projects": True,
                "has_repository_projects": True,
                "public_repos": 70,
                "public_gists": 0,
                "followers": 415,
                "following": 0,
                "html_url": "https://github.com/blacklanternsecurity",
                "created_at": "2017-01-24T00:14:46Z",
                "updated_at": "2022-03-28T11:39:03Z",
                "archived_at": None,
                "type": "Organization",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/orgs/blacklanternsecurity/repos?per_page=100&page=1",
            match_headers={"Authorization": "token asdf"},
            json=[
                {
                    "id": 459780477,
                    "node_id": "R_kgDOG2exfQ",
                    "name": "test_keys",
                    "full_name": "blacklanternsecurity/test_keys",
                    "private": False,
                    "owner": {
                        "login": "blacklanternsecurity",
                        "id": 79229934,
                        "node_id": "MDEyOk9yZ2FuaXphdGlvbjc5MjI5OTM0",
                        "avatar_url": "https://avatars.githubusercontent.com/u/79229934?v=4",
                        "gravatar_id": "",
                        "url": "https://api.github.com/users/blacklanternsecurity",
                        "html_url": "https://github.com/blacklanternsecurity",
                        "followers_url": "https://api.github.com/users/blacklanternsecurity/followers",
                        "following_url": "https://api.github.com/users/blacklanternsecurity/following{/other_user}",
                        "gists_url": "https://api.github.com/users/blacklanternsecurity/gists{/gist_id}",
                        "starred_url": "https://api.github.com/users/blacklanternsecurity/starred{/owner}{/repo}",
                        "subscriptions_url": "https://api.github.com/users/blacklanternsecurity/subscriptions",
                        "organizations_url": "https://api.github.com/users/blacklanternsecurity/orgs",
                        "repos_url": "https://api.github.com/users/blacklanternsecurity/repos",
                        "events_url": "https://api.github.com/users/blacklanternsecurity/events{/privacy}",
                        "received_events_url": "https://api.github.com/users/blacklanternsecurity/received_events",
                        "type": "Organization",
                        "site_admin": False,
                    },
                    "html_url": "https://github.com/blacklanternsecurity/test_keys",
                    "description": None,
                    "fork": False,
                    "url": "https://api.github.com/repos/blacklanternsecurity/test_keys",
                    "forks_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/forks",
                    "keys_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/keys{/key_id}",
                    "collaborators_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/collaborators{/collaborator}",
                    "teams_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/teams",
                    "hooks_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/hooks",
                    "issue_events_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/issues/events{/number}",
                    "events_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/events",
                    "assignees_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/assignees{/user}",
                    "branches_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/branches{/branch}",
                    "tags_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/tags",
                    "blobs_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/git/blobs{/sha}",
                    "git_tags_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/git/tags{/sha}",
                    "git_refs_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/git/refs{/sha}",
                    "trees_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/git/trees{/sha}",
                    "statuses_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/statuses/{sha}",
                    "languages_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/languages",
                    "stargazers_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/stargazers",
                    "contributors_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/contributors",
                    "subscribers_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/subscribers",
                    "subscription_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/subscription",
                    "commits_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/commits{/sha}",
                    "git_commits_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/git/commits{/sha}",
                    "comments_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/comments{/number}",
                    "issue_comment_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/issues/comments{/number}",
                    "contents_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/contents/{+path}",
                    "compare_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/compare/{base}...{head}",
                    "merges_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/merges",
                    "archive_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/{archive_format}{/ref}",
                    "downloads_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/downloads",
                    "issues_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/issues{/number}",
                    "pulls_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/pulls{/number}",
                    "milestones_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/milestones{/number}",
                    "notifications_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/notifications{?since,all,participating}",
                    "labels_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/labels{/name}",
                    "releases_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/releases{/id}",
                    "deployments_url": "https://api.github.com/repos/blacklanternsecurity/test_keys/deployments",
                    "created_at": "2022-02-15T23:10:51Z",
                    "updated_at": "2023-09-02T12:20:13Z",
                    "pushed_at": "2023-10-19T02:56:46Z",
                    "git_url": "git://github.com/blacklanternsecurity/test_keys.git",
                    "ssh_url": "git@github.com:blacklanternsecurity/test_keys.git",
                    "clone_url": "https://github.com/blacklanternsecurity/test_keys.git",
                    "svn_url": "https://github.com/blacklanternsecurity/test_keys",
                    "homepage": None,
                    "size": 2,
                    "stargazers_count": 2,
                    "watchers_count": 2,
                    "language": None,
                    "has_issues": True,
                    "has_projects": True,
                    "has_downloads": True,
                    "has_wiki": True,
                    "has_pages": False,
                    "has_discussions": False,
                    "forks_count": 32,
                    "mirror_url": None,
                    "archived": False,
                    "disabled": False,
                    "open_issues_count": 2,
                    "license": None,
                    "allow_forking": True,
                    "is_template": False,
                    "web_commit_signoff_required": False,
                    "topics": [],
                    "visibility": "public",
                    "forks": 32,
                    "open_issues": 2,
                    "watchers": 2,
                    "default_branch": "main",
                    "permissions": {"admin": False, "maintain": False, "push": False, "triage": False, "pull": True},
                }
            ],
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/orgs/blacklanternsecurity/members?per_page=100&page=1",
            match_headers={"Authorization": "token asdf"},
            json=[
                {
                    "login": "TheTechromancer",
                    "id": 20261699,
                    "node_id": "MDQ6VXNlcjIwMjYxNjk5",
                    "avatar_url": "https://avatars.githubusercontent.com/u/20261699?v=4",
                    "gravatar_id": "",
                    "url": "https://api.github.com/users/TheTechromancer",
                    "html_url": "https://github.com/TheTechromancer",
                    "followers_url": "https://api.github.com/users/TheTechromancer/followers",
                    "following_url": "https://api.github.com/users/TheTechromancer/following{/other_user}",
                    "gists_url": "https://api.github.com/users/TheTechromancer/gists{/gist_id}",
                    "starred_url": "https://api.github.com/users/TheTechromancer/starred{/owner}{/repo}",
                    "subscriptions_url": "https://api.github.com/users/TheTechromancer/subscriptions",
                    "organizations_url": "https://api.github.com/users/TheTechromancer/orgs",
                    "repos_url": "https://api.github.com/users/TheTechromancer/repos",
                    "events_url": "https://api.github.com/users/TheTechromancer/events{/privacy}",
                    "received_events_url": "https://api.github.com/users/TheTechromancer/received_events",
                    "type": "User",
                    "site_admin": False,
                }
            ],
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/users/TheTechromancer/repos?per_page=100&page=1",
            match_headers={"Authorization": "token asdf"},
            json=[
                {
                    "id": 688270318,
                    "node_id": "R_kgDOKQYr7g",
                    "name": "websitedemo",
                    "full_name": "TheTechromancer/websitedemo",
                    "private": False,
                    "owner": {
                        "login": "TheTechromancer",
                        "id": 20261699,
                        "node_id": "MDQ6VXNlcjIwMjYxNjk5",
                        "avatar_url": "https://avatars.githubusercontent.com/u/20261699?v=4",
                        "gravatar_id": "",
                        "url": "https://api.github.com/users/TheTechromancer",
                        "html_url": "https://github.com/TheTechromancer",
                        "followers_url": "https://api.github.com/users/TheTechromancer/followers",
                        "following_url": "https://api.github.com/users/TheTechromancer/following{/other_user}",
                        "gists_url": "https://api.github.com/users/TheTechromancer/gists{/gist_id}",
                        "starred_url": "https://api.github.com/users/TheTechromancer/starred{/owner}{/repo}",
                        "subscriptions_url": "https://api.github.com/users/TheTechromancer/subscriptions",
                        "organizations_url": "https://api.github.com/users/TheTechromancer/orgs",
                        "repos_url": "https://api.github.com/users/TheTechromancer/repos",
                        "events_url": "https://api.github.com/users/TheTechromancer/events{/privacy}",
                        "received_events_url": "https://api.github.com/users/TheTechromancer/received_events",
                        "type": "User",
                        "site_admin": False,
                    },
                    "html_url": "https://github.com/TheTechromancer/websitedemo",
                    "description": None,
                    "fork": False,
                    "url": "https://api.github.com/repos/TheTechromancer/websitedemo",
                    "forks_url": "https://api.github.com/repos/TheTechromancer/websitedemo/forks",
                    "keys_url": "https://api.github.com/repos/TheTechromancer/websitedemo/keys{/key_id}",
                    "collaborators_url": "https://api.github.com/repos/TheTechromancer/websitedemo/collaborators{/collaborator}",
                    "teams_url": "https://api.github.com/repos/TheTechromancer/websitedemo/teams",
                    "hooks_url": "https://api.github.com/repos/TheTechromancer/websitedemo/hooks",
                    "issue_events_url": "https://api.github.com/repos/TheTechromancer/websitedemo/issues/events{/number}",
                    "events_url": "https://api.github.com/repos/TheTechromancer/websitedemo/events",
                    "assignees_url": "https://api.github.com/repos/TheTechromancer/websitedemo/assignees{/user}",
                    "branches_url": "https://api.github.com/repos/TheTechromancer/websitedemo/branches{/branch}",
                    "tags_url": "https://api.github.com/repos/TheTechromancer/websitedemo/tags",
                    "blobs_url": "https://api.github.com/repos/TheTechromancer/websitedemo/git/blobs{/sha}",
                    "git_tags_url": "https://api.github.com/repos/TheTechromancer/websitedemo/git/tags{/sha}",
                    "git_refs_url": "https://api.github.com/repos/TheTechromancer/websitedemo/git/refs{/sha}",
                    "trees_url": "https://api.github.com/repos/TheTechromancer/websitedemo/git/trees{/sha}",
                    "statuses_url": "https://api.github.com/repos/TheTechromancer/websitedemo/statuses/{sha}",
                    "languages_url": "https://api.github.com/repos/TheTechromancer/websitedemo/languages",
                    "stargazers_url": "https://api.github.com/repos/TheTechromancer/websitedemo/stargazers",
                    "contributors_url": "https://api.github.com/repos/TheTechromancer/websitedemo/contributors",
                    "subscribers_url": "https://api.github.com/repos/TheTechromancer/websitedemo/subscribers",
                    "subscription_url": "https://api.github.com/repos/TheTechromancer/websitedemo/subscription",
                    "commits_url": "https://api.github.com/repos/TheTechromancer/websitedemo/commits{/sha}",
                    "git_commits_url": "https://api.github.com/repos/TheTechromancer/websitedemo/git/commits{/sha}",
                    "comments_url": "https://api.github.com/repos/TheTechromancer/websitedemo/comments{/number}",
                    "issue_comment_url": "https://api.github.com/repos/TheTechromancer/websitedemo/issues/comments{/number}",
                    "contents_url": "https://api.github.com/repos/TheTechromancer/websitedemo/contents/{+path}",
                    "compare_url": "https://api.github.com/repos/TheTechromancer/websitedemo/compare/{base}...{head}",
                    "merges_url": "https://api.github.com/repos/TheTechromancer/websitedemo/merges",
                    "archive_url": "https://api.github.com/repos/TheTechromancer/websitedemo/{archive_format}{/ref}",
                    "downloads_url": "https://api.github.com/repos/TheTechromancer/websitedemo/downloads",
                    "issues_url": "https://api.github.com/repos/TheTechromancer/websitedemo/issues{/number}",
                    "pulls_url": "https://api.github.com/repos/TheTechromancer/websitedemo/pulls{/number}",
                    "milestones_url": "https://api.github.com/repos/TheTechromancer/websitedemo/milestones{/number}",
                    "notifications_url": "https://api.github.com/repos/TheTechromancer/websitedemo/notifications{?since,all,participating}",
                    "labels_url": "https://api.github.com/repos/TheTechromancer/websitedemo/labels{/name}",
                    "releases_url": "https://api.github.com/repos/TheTechromancer/websitedemo/releases{/id}",
                    "deployments_url": "https://api.github.com/repos/TheTechromancer/websitedemo/deployments",
                    "created_at": "2023-09-07T02:18:28Z",
                    "updated_at": "2023-09-07T02:20:18Z",
                    "pushed_at": "2023-09-07T02:34:45Z",
                    "git_url": "git://github.com/TheTechromancer/websitedemo.git",
                    "ssh_url": "git@github.com:TheTechromancer/websitedemo.git",
                    "clone_url": "https://github.com/TheTechromancer/websitedemo.git",
                    "svn_url": "https://github.com/TheTechromancer/websitedemo",
                    "homepage": None,
                    "size": 1,
                    "stargazers_count": 0,
                    "watchers_count": 0,
                    "language": "HTML",
                    "has_issues": True,
                    "has_projects": True,
                    "has_downloads": True,
                    "has_wiki": True,
                    "has_pages": True,
                    "has_discussions": False,
                    "forks_count": 0,
                    "mirror_url": None,
                    "archived": False,
                    "disabled": False,
                    "open_issues_count": 0,
                    "license": None,
                    "allow_forking": True,
                    "is_template": False,
                    "web_commit_signoff_required": False,
                    "topics": [],
                    "visibility": "public",
                    "forks": 0,
                    "open_issues": 0,
                    "watchers": 0,
                    "default_branch": "main",
                }
            ],
        )

    def check(self, module_test, events):
        assert len(events) == 7
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com" and e.scope_distance == 0
            ]
        ), "Failed to emit target DNS_NAME"
        assert 1 == len(
            [e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity" and e.scope_distance == 0]
        ), "Failed to find ORG_STUB"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "blacklanternsecurity"
                and str(e.module) == "github_org"
                and "github-org" in e.tags
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity github"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "TheTechromancer"
                and str(e.module) == "github_org"
                and "github-org-member" in e.tags
                and e.scope_distance == 2
            ]
        ), "Failed to find TheTechromancer github"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://github.com/blacklanternsecurity/test_keys"
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity github repo"


class TestGithub_Org_No_Members(TestGithub_Org):
    config_overrides = {"modules": {"github_org": {"include_members": False}, "github": {"api_key": "asdf"}}}

    def check(self, module_test, events):
        assert len(events) == 6
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "blacklanternsecurity"
                and str(e.module) == "github_org"
                and "github-org" in e.tags
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity github"
        assert 0 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "TheTechromancer"
            ]
        ), "Found TheTechromancer github"


class TestGithub_Org_MemberRepos(TestGithub_Org):
    config_overrides = {"modules": {"github_org": {"include_member_repos": True}, "github": {"api_key": "asdf"}}}

    def check(self, module_test, events):
        assert len(events) == 8
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://github.com/TheTechromancer/websitedemo"
                and e.scope_distance == 2
            ]
        ), "Failed to find TheTechromancer github repo"


class TestGithub_Org_Custom_Target(TestGithub_Org):
    targets = ["ORG:blacklanternsecurity"]
    config_overrides = {
        "scope": {"report_distance": 10},
        "omit_event_types": [],
        "speculate": True,
        "modules": {"github": {"api_key": "asdf"}},
    }

    def check(self, module_test, events):
        assert len(events) == 8
        assert 1 == len(
            [e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity" and e.scope_distance == 0]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "blacklanternsecurity"
                and e.scope_distance == 1
                and str(e.module) == "github_org"
                and e.parent.type == "ORG_STUB"
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "github.com" and e.scope_distance == 1]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and e.data == "https://github.com/blacklanternsecurity"
                and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and e.data["url"] == "https://github.com/blacklanternsecurity/test_keys"
                and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "TheTechromancer"
                and e.scope_distance == 2
            ]
        )
