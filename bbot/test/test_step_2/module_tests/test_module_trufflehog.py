import subprocess
import shutil
import io
import zipfile
import tarfile
from pathlib import Path

from .base import ModuleTestBase


class TestTrufflehog(ModuleTestBase):
    config_overrides = {"modules": {"postman_download": {"api_key": "asdf"}}}
    modules_overrides = [
        "github_org",
        "speculate",
        "git_clone",
        "github_workflows",
        "dockerhub",
        "docker_pull",
        "postman",
        "postman_download",
        "trufflehog",
    ]

    file_content = "Verifyable Secret:\nhttps://admin:admin@the-internet.herokuapp.com/basic_auth\n\nUnverifyable Secret:\nhttps://admin:admin@internal.host.com"

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(url="https://api.github.com/zen")
        module_test.httpx_mock.add_response(
            url="https://api.getpostman.com/me",
            json={
                "user": {
                    "id": 000000,
                    "username": "test_key",
                    "email": "blacklanternsecurity@test.com",
                    "fullName": "Test Key",
                    "avatar": "",
                    "isPublic": True,
                    "teamId": 0,
                    "teamDomain": "",
                    "roles": ["user"],
                },
                "operations": [
                    {"name": "api_object_usage", "limit": 3, "usage": 0, "overage": 0},
                    {"name": "collection_run_limit", "limit": 25, "usage": 0, "overage": 0},
                    {"name": "file_storage_limit", "limit": 20, "usage": 0, "overage": 0},
                    {"name": "flow_count", "limit": 5, "usage": 0, "overage": 0},
                    {"name": "flow_requests", "limit": 5000, "usage": 0, "overage": 0},
                    {"name": "performance_test_limit", "limit": 25, "usage": 0, "overage": 0},
                    {"name": "postbot_calls", "limit": 50, "usage": 0, "overage": 0},
                    {"name": "reusable_packages", "limit": 3, "usage": 0, "overage": 0},
                    {"name": "test_data_retrieval", "limit": 1000, "usage": 0, "overage": 0},
                    {"name": "test_data_storage", "limit": 10, "usage": 0, "overage": 0},
                    {"name": "mock_usage", "limit": 1000, "usage": 0, "overage": 0},
                    {"name": "monitor_request_runs", "limit": 1000, "usage": 0, "overage": 0},
                    {"name": "api_usage", "limit": 1000, "usage": 0, "overage": 0},
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/orgs/blacklanternsecurity",
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
                },
                {
                    "id": 459780477,
                    "node_id": "R_kgDOG2exfQ",
                    "name": "bbot",
                    "full_name": "blacklanternsecurity/bbot",
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
                    "html_url": "https://github.com/blacklanternsecurity/bbot",
                    "description": None,
                    "fork": False,
                    "url": "https://api.github.com/repos/blacklanternsecurity/bbot",
                    "forks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/forks",
                    "keys_url": "https://api.github.com/repos/blacklanternsecurity/bbot/keys{/key_id}",
                    "collaborators_url": "https://api.github.com/repos/blacklanternsecurity/bbot/collaborators{/collaborator}",
                    "teams_url": "https://api.github.com/repos/blacklanternsecurity/bbot/teams",
                    "hooks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/hooks",
                    "issue_events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/events{/number}",
                    "events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/events",
                    "assignees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/assignees{/user}",
                    "branches_url": "https://api.github.com/repos/blacklanternsecurity/bbot/branches{/branch}",
                    "tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/tags",
                    "blobs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/blobs{/sha}",
                    "git_tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/tags{/sha}",
                    "git_refs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/refs{/sha}",
                    "trees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/trees{/sha}",
                    "statuses_url": "https://api.github.com/repos/blacklanternsecurity/bbot/statuses/{sha}",
                    "languages_url": "https://api.github.com/repos/blacklanternsecurity/bbot/languages",
                    "stargazers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/stargazers",
                    "contributors_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contributors",
                    "subscribers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscribers",
                    "subscription_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscription",
                    "commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/commits{/sha}",
                    "git_commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/commits{/sha}",
                    "comments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/comments{/number}",
                    "issue_comment_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/comments{/number}",
                    "contents_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contents/{+path}",
                    "compare_url": "https://api.github.com/repos/blacklanternsecurity/bbot/compare/{base}...{head}",
                    "merges_url": "https://api.github.com/repos/blacklanternsecurity/bbot/merges",
                    "archive_url": "https://api.github.com/repos/blacklanternsecurity/bbot/{archive_format}{/ref}",
                    "downloads_url": "https://api.github.com/repos/blacklanternsecurity/bbot/downloads",
                    "issues_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues{/number}",
                    "pulls_url": "https://api.github.com/repos/blacklanternsecurity/bbot/pulls{/number}",
                    "milestones_url": "https://api.github.com/repos/blacklanternsecurity/bbot/milestones{/number}",
                    "notifications_url": "https://api.github.com/repos/blacklanternsecurity/bbot/notifications{?since,all,participating}",
                    "labels_url": "https://api.github.com/repos/blacklanternsecurity/bbot/labels{/name}",
                    "releases_url": "https://api.github.com/repos/blacklanternsecurity/bbot/releases{/id}",
                    "deployments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/deployments",
                    "created_at": "2022-02-15T23:10:51Z",
                    "updated_at": "2023-09-02T12:20:13Z",
                    "pushed_at": "2023-10-19T02:56:46Z",
                    "git_url": "git://github.com/blacklanternsecurity/bbot.git",
                    "ssh_url": "git@github.com:blacklanternsecurity/bbot.git",
                    "clone_url": "https://github.com/blacklanternsecurity/bbot.git",
                    "svn_url": "https://github.com/blacklanternsecurity/bbot",
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
                },
            ],
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/repos/blacklanternsecurity/bbot/actions/workflows?per_page=100&page=1",
            json={
                "total_count": 3,
                "workflows": [
                    {
                        "id": 22452226,
                        "node_id": "W_kwDOG_O3ns4BVpgC",
                        "name": "tests",
                        "path": ".github/workflows/tests.yml",
                        "state": "active",
                        "created_at": "2022-03-23T15:09:22.000Z",
                        "updated_at": "2022-09-27T17:49:34.000Z",
                        "url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/workflows/22452226",
                        "html_url": "https://github.com/blacklanternsecurity/bbot/blob/stable/.github/workflows/tests.yml",
                        "badge_url": "https://github.com/blacklanternsecurity/bbot/workflows/tests/badge.svg",
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/repos/blacklanternsecurity/bbot/actions/workflows/22452226/runs?status=success&per_page=1",
            json={
                "total_count": 2993,
                "workflow_runs": [
                    {
                        "id": 8839360698,
                        "name": "tests",
                        "node_id": "WFR_kwLOG_O3ns8AAAACDt3wug",
                        "head_branch": "dnsbrute-helperify",
                        "head_sha": "c5de1360e8e5ccba04b23035f675a529282b7dc2",
                        "path": ".github/workflows/tests.yml",
                        "display_title": "Helperify Massdns",
                        "run_number": 4520,
                        "event": "pull_request",
                        "status": "completed",
                        "conclusion": "success",
                        "workflow_id": 22452226,
                        "check_suite_id": 23162098295,
                        "check_suite_node_id": "CS_kwDOG_O3ns8AAAAFZJGSdw",
                        "url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698",
                        "html_url": "https://github.com/blacklanternsecurity/bbot/actions/runs/8839360698",
                        "pull_requests": [
                            {
                                "url": "https://api.github.com/repos/blacklanternsecurity/bbot/pulls/1303",
                                "id": 1839332952,
                                "number": 1303,
                                "head": {
                                    "ref": "dnsbrute-helperify",
                                    "sha": "c5de1360e8e5ccba04b23035f675a529282b7dc2",
                                    "repo": {
                                        "id": 468957086,
                                        "url": "https://api.github.com/repos/blacklanternsecurity/bbot",
                                        "name": "bbot",
                                    },
                                },
                                "base": {
                                    "ref": "faster-regexes",
                                    "sha": "7baf219c7f3a4ba165639c5ddb62322453a8aea8",
                                    "repo": {
                                        "id": 468957086,
                                        "url": "https://api.github.com/repos/blacklanternsecurity/bbot",
                                        "name": "bbot",
                                    },
                                },
                            }
                        ],
                        "created_at": "2024-04-25T21:04:32Z",
                        "updated_at": "2024-04-25T21:19:43Z",
                        "actor": {
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
                        "run_attempt": 1,
                        "referenced_workflows": [],
                        "run_started_at": "2024-04-25T21:04:32Z",
                        "triggering_actor": {
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
                        "jobs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/jobs",
                        "logs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/logs",
                        "check_suite_url": "https://api.github.com/repos/blacklanternsecurity/bbot/check-suites/23162098295",
                        "artifacts_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/artifacts",
                        "cancel_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/cancel",
                        "rerun_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/rerun",
                        "previous_attempt_url": None,
                        "workflow_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/workflows/22452226",
                        "head_commit": {
                            "id": "c5de1360e8e5ccba04b23035f675a529282b7dc2",
                            "tree_id": "fe9b345c0745a5bbacb806225e92e1c48fccf35c",
                            "message": "remove debug message",
                            "timestamp": "2024-04-25T21:02:37Z",
                            "author": {"name": "TheTechromancer", "email": "thetechromancer@protonmail.com"},
                            "committer": {"name": "TheTechromancer", "email": "thetechromancer@protonmail.com"},
                        },
                        "repository": {
                            "id": 468957086,
                            "node_id": "R_kgDOG_O3ng",
                            "name": "bbot",
                            "full_name": "blacklanternsecurity/bbot",
                            "private": False,
                            "owner": {
                                "login": "blacklanternsecurity",
                                "id": 25311592,
                                "node_id": "MDEyOk9yZ2FuaXphdGlvbjI1MzExNTky",
                                "avatar_url": "https://avatars.githubusercontent.com/u/25311592?v=4",
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
                            "html_url": "https://github.com/blacklanternsecurity/bbot",
                            "description": "A recursive internet scanner for hackers.",
                            "fork": False,
                            "url": "https://api.github.com/repos/blacklanternsecurity/bbot",
                            "forks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/forks",
                            "keys_url": "https://api.github.com/repos/blacklanternsecurity/bbot/keys{/key_id}",
                            "collaborators_url": "https://api.github.com/repos/blacklanternsecurity/bbot/collaborators{/collaborator}",
                            "teams_url": "https://api.github.com/repos/blacklanternsecurity/bbot/teams",
                            "hooks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/hooks",
                            "issue_events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/events{/number}",
                            "events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/events",
                            "assignees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/assignees{/user}",
                            "branches_url": "https://api.github.com/repos/blacklanternsecurity/bbot/branches{/branch}",
                            "tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/tags",
                            "blobs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/blobs{/sha}",
                            "git_tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/tags{/sha}",
                            "git_refs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/refs{/sha}",
                            "trees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/trees{/sha}",
                            "statuses_url": "https://api.github.com/repos/blacklanternsecurity/bbot/statuses/{sha}",
                            "languages_url": "https://api.github.com/repos/blacklanternsecurity/bbot/languages",
                            "stargazers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/stargazers",
                            "contributors_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contributors",
                            "subscribers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscribers",
                            "subscription_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscription",
                            "commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/commits{/sha}",
                            "git_commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/commits{/sha}",
                            "comments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/comments{/number}",
                            "issue_comment_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/comments{/number}",
                            "contents_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contents/{+path}",
                            "compare_url": "https://api.github.com/repos/blacklanternsecurity/bbot/compare/{base}...{head}",
                            "merges_url": "https://api.github.com/repos/blacklanternsecurity/bbot/merges",
                            "archive_url": "https://api.github.com/repos/blacklanternsecurity/bbot/{archive_format}{/ref}",
                            "downloads_url": "https://api.github.com/repos/blacklanternsecurity/bbot/downloads",
                            "issues_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues{/number}",
                            "pulls_url": "https://api.github.com/repos/blacklanternsecurity/bbot/pulls{/number}",
                            "milestones_url": "https://api.github.com/repos/blacklanternsecurity/bbot/milestones{/number}",
                            "notifications_url": "https://api.github.com/repos/blacklanternsecurity/bbot/notifications{?since,all,participating}",
                            "labels_url": "https://api.github.com/repos/blacklanternsecurity/bbot/labels{/name}",
                            "releases_url": "https://api.github.com/repos/blacklanternsecurity/bbot/releases{/id}",
                            "deployments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/deployments",
                        },
                        "head_repository": {
                            "id": 468957086,
                            "node_id": "R_kgDOG_O3ng",
                            "name": "bbot",
                            "full_name": "blacklanternsecurity/bbot",
                            "private": False,
                            "owner": {
                                "login": "blacklanternsecurity",
                                "id": 25311592,
                                "node_id": "MDEyOk9yZ2FuaXphdGlvbjI1MzExNTky",
                                "avatar_url": "https://avatars.githubusercontent.com/u/25311592?v=4",
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
                            "html_url": "https://github.com/blacklanternsecurity/bbot",
                            "description": "A recursive internet scanner for hackers.",
                            "fork": False,
                            "url": "https://api.github.com/repos/blacklanternsecurity/bbot",
                            "forks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/forks",
                            "keys_url": "https://api.github.com/repos/blacklanternsecurity/bbot/keys{/key_id}",
                            "collaborators_url": "https://api.github.com/repos/blacklanternsecurity/bbot/collaborators{/collaborator}",
                            "teams_url": "https://api.github.com/repos/blacklanternsecurity/bbot/teams",
                            "hooks_url": "https://api.github.com/repos/blacklanternsecurity/bbot/hooks",
                            "issue_events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/events{/number}",
                            "events_url": "https://api.github.com/repos/blacklanternsecurity/bbot/events",
                            "assignees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/assignees{/user}",
                            "branches_url": "https://api.github.com/repos/blacklanternsecurity/bbot/branches{/branch}",
                            "tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/tags",
                            "blobs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/blobs{/sha}",
                            "git_tags_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/tags{/sha}",
                            "git_refs_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/refs{/sha}",
                            "trees_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/trees{/sha}",
                            "statuses_url": "https://api.github.com/repos/blacklanternsecurity/bbot/statuses/{sha}",
                            "languages_url": "https://api.github.com/repos/blacklanternsecurity/bbot/languages",
                            "stargazers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/stargazers",
                            "contributors_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contributors",
                            "subscribers_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscribers",
                            "subscription_url": "https://api.github.com/repos/blacklanternsecurity/bbot/subscription",
                            "commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/commits{/sha}",
                            "git_commits_url": "https://api.github.com/repos/blacklanternsecurity/bbot/git/commits{/sha}",
                            "comments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/comments{/number}",
                            "issue_comment_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues/comments{/number}",
                            "contents_url": "https://api.github.com/repos/blacklanternsecurity/bbot/contents/{+path}",
                            "compare_url": "https://api.github.com/repos/blacklanternsecurity/bbot/compare/{base}...{head}",
                            "merges_url": "https://api.github.com/repos/blacklanternsecurity/bbot/merges",
                            "archive_url": "https://api.github.com/repos/blacklanternsecurity/bbot/{archive_format}{/ref}",
                            "downloads_url": "https://api.github.com/repos/blacklanternsecurity/bbot/downloads",
                            "issues_url": "https://api.github.com/repos/blacklanternsecurity/bbot/issues{/number}",
                            "pulls_url": "https://api.github.com/repos/blacklanternsecurity/bbot/pulls{/number}",
                            "milestones_url": "https://api.github.com/repos/blacklanternsecurity/bbot/milestones{/number}",
                            "notifications_url": "https://api.github.com/repos/blacklanternsecurity/bbot/notifications{?since,all,participating}",
                            "labels_url": "https://api.github.com/repos/blacklanternsecurity/bbot/labels{/name}",
                            "releases_url": "https://api.github.com/repos/blacklanternsecurity/bbot/releases{/id}",
                            "deployments_url": "https://api.github.com/repos/blacklanternsecurity/bbot/deployments",
                        },
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/logs",
            headers={
                "location": "https://productionresultssa10.blob.core.windows.net/actions-results/7beb304e-f42c-4830-a027-4f5dec53107d/workflow-job-run-3a559e2a-952e-58d2-b8db-2e604a9266d7/logs/steps/step-logs-0e34a19a-18b0-4208-b27a-f8c031db2d17.txt?rsct=text%2Fplain&se=2024-04-26T16%3A25%3A39Z&sig=a%2FiN8dOw0e3tiBQZAfr80veI8OYChb9edJ1eFY136B4%3D&sp=r&spr=https&sr=b&st=2024-04-26T16%3A15%3A34Z&sv=2021-12-02"
            },
            status_code=302,
        )
        data = io.BytesIO()
        with zipfile.ZipFile(data, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("test.txt", self.file_content)
            z.writestr("folder/test2.txt", self.file_content)
        data.seek(0)
        zip_content = data.getvalue()
        module_test.httpx_mock.add_response(
            url="https://productionresultssa10.blob.core.windows.net/actions-results/7beb304e-f42c-4830-a027-4f5dec53107d/workflow-job-run-3a559e2a-952e-58d2-b8db-2e604a9266d7/logs/steps/step-logs-0e34a19a-18b0-4208-b27a-f8c031db2d17.txt?rsct=text%2Fplain&se=2024-04-26T16%3A25%3A39Z&sig=a%2FiN8dOw0e3tiBQZAfr80veI8OYChb9edJ1eFY136B4%3D&sp=r&spr=https&sr=b&st=2024-04-26T16%3A15%3A34Z&sv=2021-12-02",
            content=zip_content,
        )
        module_test.httpx_mock.add_response(
            url="https://hub.docker.com/v2/users/blacklanternsecurity",
            json={
                "id": "f90895d9cf484d9182c6dbbef2632329",
                "uuid": "f90895d9-cf48-4d91-82c6-dbbef2632329",
                "username": "blacklanternsecurity",
                "full_name": "",
                "location": "",
                "company": "Black Lantern Security",
                "profile_url": "https://github.com/blacklanternsecurity",
                "date_joined": "2022-08-29T15:27:10.227081Z",
                "gravatar_url": "",
                "gravatar_email": "",
                "type": "User",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/blacklanternsecurity?page_size=25&page=1",
            json={
                "count": 2,
                "next": None,
                "previous": None,
                "results": [
                    {
                        "name": "helloworld",
                        "namespace": "blacklanternsecurity",
                        "repository_type": "image",
                        "status": 1,
                        "status_description": "active",
                        "description": "",
                        "is_private": False,
                        "star_count": 0,
                        "pull_count": 1,
                        "last_updated": "2021-12-20T17:19:58.88296Z",
                        "date_registered": "2021-12-20T17:19:58.507614Z",
                        "affiliation": "",
                        "media_types": ["application/vnd.docker.container.image.v1+json"],
                        "content_types": ["image"],
                        "categories": [],
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/tags/list",
            json={
                "name": "blacklanternsecurity/helloworld",
                "tags": [
                    "dev",
                    "latest",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/manifests/latest",
            json={
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 8614,
                    "digest": "sha256:a9910947b74a4f0606cfc8669ae8808d2c328beaee9e79f489dc17df14cd50b1",
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                        "size": 29124181,
                        "digest": "sha256:8a1e25ce7c4f75e372e9884f8f7b1bedcfe4a7a7d452eb4b0a1c7477c9a90345",
                    },
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/blobs/sha256:a9910947b74a4f0606cfc8669ae8808d2c328beaee9e79f489dc17df14cd50b1",
            json={
                "architecture": "amd64",
                "config": {
                    "Env": [
                        "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG=C.UTF-8",
                        "GPG_KEY=QWERTYUIOPASDFGHJKLZXCBNM",
                        "PYTHON_VERSION=3.10.14",
                        "PYTHON_PIP_VERSION=23.0.1",
                        "PYTHON_SETUPTOOLS_VERSION=65.5.1",
                        "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
                        "PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9",
                        "LC_ALL=C.UTF-8",
                        "PIP_NO_CACHE_DIR=off",
                    ],
                    "Entrypoint": ["helloworld"],
                    "WorkingDir": "/root",
                    "ArgsEscaped": True,
                    "OnBuild": None,
                },
                "created": "2024-03-24T03:46:29.788993495Z",
                "history": [
                    {
                        "created": "2024-03-12T01:21:01.529814652Z",
                        "created_by": "/bin/sh -c #(nop) ADD file:b86ae1c7ca3586d8feedcd9ff1b2b1e8ab872caf6587618f1da689045a5d7ae4 in / ",
                    },
                    {
                        "created": "2024-03-12T01:21:01.866693306Z",
                        "created_by": '/bin/sh -c #(nop)  CMD ["bash"]',
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV LANG=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "RUN /bin/sh -c set -eux; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tca-certificates \t\tnetbase \t\ttzdata \t; \trm -rf /var/lib/apt/lists/* # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV GPG_KEY=QWERTYUIOPASDFGHJKLZXCBNM",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_VERSION=3.10.14",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \t\tsavedAptMark="$(apt-mark showmanual)"; \tapt-get update; \tapt-get install -y --no-install-recommends \t\tdpkg-dev \t\tgcc \t\tgnupg \t\tlibbluetooth-dev \t\tlibbz2-dev \t\tlibc6-dev \t\tlibdb-dev \t\tlibexpat1-dev \t\tlibffi-dev \t\tlibgdbm-dev \t\tliblzma-dev \t\tlibncursesw5-dev \t\tlibreadline-dev \t\tlibsqlite3-dev \t\tlibssl-dev \t\tmake \t\ttk-dev \t\tuuid-dev \t\twget \t\txz-utils \t\tzlib1g-dev \t; \t\twget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \twget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; \tGNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \tgpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; \tgpg --batch --verify python.tar.xz.asc python.tar.xz; \tgpgconf --kill all; \trm -rf "$GNUPGHOME" python.tar.xz.asc; \tmkdir -p /usr/src/python; \ttar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \trm python.tar.xz; \t\tcd /usr/src/python; \tgnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \t./configure \t\t--build="$gnuArch" \t\t--enable-loadable-sqlite-extensions \t\t--enable-optimizations \t\t--enable-option-checking=fatal \t\t--enable-shared \t\t--with-lto \t\t--with-system-expat \t\t--without-ensurepip \t; \tnproc="$(nproc)"; \tEXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; \tLDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; \tLDFLAGS="${LDFLAGS:--Wl},--strip-all"; \tmake -j "$nproc" \t\t"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \t\t"LDFLAGS=${LDFLAGS:-}" \t\t"PROFILE_TASK=${PROFILE_TASK:-}" \t; \trm python; \tmake -j "$nproc" \t\t"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \t\t"LDFLAGS=${LDFLAGS:--Wl},-rpath=\'\\$\\$ORIGIN/../lib\'" \t\t"PROFILE_TASK=${PROFILE_TASK:-}" \t\tpython \t; \tmake install; \t\tcd /; \trm -rf /usr/src/python; \t\tfind /usr/local -depth \t\t\\( \t\t\t\\( -type d -a \\( -name test -o -name tests -o -name idle_test \\) \\) \t\t\t-o \\( -type f -a \\( -name \'*.pyc\' -o -name \'*.pyo\' -o -name \'libpython*.a\' \\) \\) \t\t\\) -exec rm -rf \'{}\' + \t; \t\tldconfig; \t\tapt-mark auto \'.*\' > /dev/null; \tapt-mark manual $savedAptMark; \tfind /usr/local -type f -executable -not \\( -name \'*tkinter*\' \\) -exec ldd \'{}\' \';\' \t\t| awk \'/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\\n", so }\' \t\t| sort -u \t\t| xargs -r dpkg-query --search \t\t| cut -d: -f1 \t\t| sort -u \t\t| xargs -r apt-mark manual \t; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\tpython3 --version # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \tfor src in idle3 pydoc3 python3 python3-config; do \t\tdst="$(echo "$src" | tr -d 3)"; \t\t[ -s "/usr/local/bin/$src" ]; \t\t[ ! -e "/usr/local/bin/$dst" ]; \t\tln -svT "$src" "/usr/local/bin/$dst"; \tdone # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_PIP_VERSION=23.0.1",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_SETUPTOOLS_VERSION=65.5.1",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": "ENV PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'RUN /bin/sh -c set -eux; \t\tsavedAptMark="$(apt-mark showmanual)"; \tapt-get update; \tapt-get install -y --no-install-recommends wget; \t\twget -O get-pip.py "$PYTHON_GET_PIP_URL"; \techo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum -c -; \t\tapt-mark auto \'.*\' > /dev/null; \t[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \tapt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \trm -rf /var/lib/apt/lists/*; \t\texport PYTHONDONTWRITEBYTECODE=1; \t\tpython get-pip.py \t\t--disable-pip-version-check \t\t--no-cache-dir \t\t--no-compile \t\t"pip==$PYTHON_PIP_VERSION" \t\t"setuptools==$PYTHON_SETUPTOOLS_VERSION" \t; \trm -f get-pip.py; \t\tpip --version # buildkit',
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-20T18:33:29Z",
                        "created_by": 'CMD ["python3"]',
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV LANG=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV LC_ALL=C.UTF-8",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "ENV PIP_NO_CACHE_DIR=off",
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                    {
                        "created": "2024-03-24T03:45:39.322168741Z",
                        "created_by": "WORKDIR /usr/src/helloworld",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:45:52.226201188Z",
                        "created_by": "RUN /bin/sh -c apt-get update && apt-get install -y openssl gcc git make unzip curl wget vim nano sudo # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:45:52.391597947Z",
                        "created_by": "COPY . . # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.76589069Z",
                        "created_by": "RUN /bin/sh -c pip install . # buildkit",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.788993495Z",
                        "created_by": "WORKDIR /root",
                        "comment": "buildkit.dockerfile.v0",
                    },
                    {
                        "created": "2024-03-24T03:46:29.788993495Z",
                        "created_by": 'ENTRYPOINT ["helloworld"]',
                        "comment": "buildkit.dockerfile.v0",
                        "empty_layer": True,
                    },
                ],
                "os": "linux",
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [
                        "sha256:a483da8ab3e941547542718cacd3258c6c705a63e94183c837c9bc44eb608999",
                        "sha256:c8f253aef5606f6716778771171c3fdf6aa135b76a5fa8bf66ba45c12c15b540",
                        "sha256:b4a9dcc697d250c7be53887bb8e155c8f7a06f9c63a3aa627c647bb4a426d3f0",
                        "sha256:120fda24c420b4e5d52f1c288b35c75b07969057bce41ec34cfb05606b2d7c11",
                        "sha256:c2287f03e33f4896b2720f0cb64e6b6050759a3eb5914e531e98fc3499b4e687",
                        "sha256:afe6e55a5cf240c050a4d2b72ec7b7d009a131cba8fe2753e453a8e62ef7e45c",
                        "sha256:ae6df275ba2e8f40c598e30588afe43f6bfa92e4915e8450b77cb5db5c89dfd5",
                        "sha256:621ab22fb386a9e663178637755b651beddc0eb4762804e74d8996cce0ddd441",
                        "sha256:4c534ad16bd2df668c0b8f637616517746ede530ba8546d85f28772bc748e06f",
                        "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
                    ],
                },
            },
        )
        temp_path = Path("/tmp/.bbot_test")
        tar_path = temp_path / "docker_pull_test.tar.gz"
        shutil.rmtree(tar_path, ignore_errors=True)
        with tarfile.open(tar_path, "w:gz") as tar:
            file_io = io.BytesIO(self.file_content.encode())
            file_info = tarfile.TarInfo(name="file.txt")
            file_info.size = len(file_io.getvalue())
            file_io.seek(0)
            tar.addfile(file_info, file_io)
        with open(tar_path, "rb") as file:
            layer_file = file.read()
        module_test.httpx_mock.add_response(
            url="https://registry-1.docker.io/v2/blacklanternsecurity/helloworld/blobs/sha256:8a1e25ce7c4f75e372e9884f8f7b1bedcfe4a7a7d452eb4b0a1c7477c9a90345",
            content=layer_file,
        )

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/ws/proxy",
            match_content=b'{"service": "search", "method": "POST", "path": "/search-all", "body": {"queryIndices": ["collaboration.workspace"], "queryText": "blacklanternsecurity", "size": 100, "from": 0, "clientTraceId": "", "requestOrigin": "srp", "mergeEntities": "true", "nonNestedRequests": "true", "domain": "public"}}',
            json={
                "data": [
                    {
                        "score": 611.41156,
                        "normalizedScore": 23,
                        "document": {
                            "watcherCount": 6,
                            "apiCount": 0,
                            "forkCount": 0,
                            "isblacklisted": "false",
                            "createdAt": "2021-06-15T14:03:51",
                            "publishertype": "team",
                            "publisherHandle": "blacklanternsecurity",
                            "id": "11498add-357d-4bc5-a008-0a2d44fb8829",
                            "slug": "bbot-public",
                            "updatedAt": "2024-07-30T11:00:35",
                            "entityType": "workspace",
                            "visibilityStatus": "public",
                            "forkcount": "0",
                            "tags": [],
                            "createdat": "2021-06-15T14:03:51",
                            "forkLabel": "",
                            "publisherName": "blacklanternsecurity",
                            "name": "BlackLanternSecurity BBOT [Public]",
                            "dependencyCount": 7,
                            "collectionCount": 6,
                            "warehouse__updated_at": "2024-07-30 11:00:00",
                            "privateNetworkFolders": [],
                            "isPublisherVerified": False,
                            "publisherType": "team",
                            "curatedInList": [],
                            "creatorId": "6900157",
                            "description": "",
                            "forklabel": "",
                            "publisherId": "299401",
                            "publisherLogo": "",
                            "popularity": 5,
                            "isPublic": True,
                            "categories": [],
                            "universaltags": "",
                            "views": 5788,
                            "summary": "BLS public workspaces.",
                            "memberCount": 2,
                            "isBlacklisted": False,
                            "publisherid": "299401",
                            "isPrivateNetworkEntity": False,
                            "isDomainNonTrivial": True,
                            "privateNetworkMeta": "",
                            "updatedat": "2021-10-20T16:19:29",
                            "documentType": "workspace",
                        },
                        "highlight": {"summary": "<b>BLS</b> BBOT api test."},
                    },
                ],
                "meta": {
                    "queryText": "blacklanternsecurity",
                    "total": {
                        "collection": 0,
                        "request": 0,
                        "workspace": 1,
                        "api": 0,
                        "team": 0,
                        "user": 0,
                        "flow": 0,
                        "apiDefinition": 0,
                        "privateNetworkFolder": 0,
                    },
                    "state": "AQ4",
                    "spellCorrection": {"count": {"all": 1, "workspace": 1}, "correctedQueryText": None},
                    "featureFlags": {
                        "enabledPublicResultCuration": True,
                        "boostByPopularity": True,
                        "reRankPostNormalization": True,
                        "enableUrlBarHostNameSearch": True,
                    },
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/ws/proxy",
            match_content=b'{"service": "workspaces", "method": "GET", "path": "/workspaces?handle=blacklanternsecurity&slug=bbot-public"}',
            json={
                "meta": {"model": "workspace", "action": "find", "nextCursor": ""},
                "data": [
                    {
                        "id": "3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b",
                        "name": "BlackLanternSecurity BBOT [Public]",
                        "description": None,
                        "summary": "BLS public workspaces.",
                        "createdBy": "299401",
                        "updatedBy": "299401",
                        "team": None,
                        "createdAt": "2021-10-20T16:19:29",
                        "updatedAt": "2021-10-20T16:19:29",
                        "visibilityStatus": "public",
                        "profileInfo": {
                            "slug": "bbot-public",
                            "profileType": "team",
                            "profileId": "000000",
                            "publicHandle": "https://www.postman.com/blacklanternsecurity",
                            "publicImageURL": "",
                            "publicName": "BlackLanternSecurity",
                            "isVerified": False,
                        },
                    }
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.getpostman.com/workspaces/3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b",
            json={
                "workspace": {
                    "id": "3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b",
                    "name": "BlackLanternSecurity BBOT [Public]",
                    "type": "personal",
                    "description": None,
                    "visibility": "public",
                    "createdBy": "00000000",
                    "updatedBy": "00000000",
                    "createdAt": "2021-11-17T06:09:01.000Z",
                    "updatedAt": "2021-11-17T08:57:16.000Z",
                    "collections": [
                        {
                            "id": "2aab9fd0-3715-4abe-8bb0-8cb0264d023f",
                            "name": "BBOT Public",
                            "uid": "10197090-2aab9fd0-3715-4abe-8bb0-8cb0264d023f",
                        },
                    ],
                    "environments": [
                        {
                            "id": "f770f816-9c6a-40f7-bde3-c0855d2a1089",
                            "name": "BBOT Test",
                            "uid": "10197090-f770f816-9c6a-40f7-bde3-c0855d2a1089",
                        }
                    ],
                    "apis": [],
                }
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/workspace/3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b/globals",
            json={
                "model_id": "8be7574b-219f-49e0-8d25-da447a882e4e",
                "meta": {"model": "globals", "action": "find"},
                "data": {
                    "workspace": "3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b",
                    "lastUpdatedBy": "00000000",
                    "lastRevision": 1637239113000,
                    "id": "8be7574b-219f-49e0-8d25-da447a882e4e",
                    "values": [
                        {
                            "key": "endpoint_url",
                            "value": "https://api.blacklanternsecurity.com/",
                            "enabled": True,
                        },
                    ],
                    "createdAt": "2021-11-17T06:09:01.000Z",
                    "updatedAt": "2021-11-18T12:38:33.000Z",
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.getpostman.com/environments/10197090-f770f816-9c6a-40f7-bde3-c0855d2a1089",
            json={
                "environment": {
                    "id": "f770f816-9c6a-40f7-bde3-c0855d2a1089",
                    "name": "BBOT Test",
                    "owner": "00000000",
                    "createdAt": "2021-11-17T06:29:54.000Z",
                    "updatedAt": "2021-11-23T07:06:53.000Z",
                    "values": [
                        {
                            "key": "temp_session_endpoint",
                            "value": "https://api.blacklanternsecurity.com/",
                            "enabled": True,
                        },
                    ],
                    "isPublic": True,
                }
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.getpostman.com/collections/10197090-2aab9fd0-3715-4abe-8bb0-8cb0264d023f",
            json={
                "collection": {
                    "info": {
                        "_postman_id": "62b91565-d2e2-4bcd-8248-4dba2e3452f0",
                        "name": "BBOT Public",
                        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                        "updatedAt": "2021-11-17T07:13:16.000Z",
                        "createdAt": "2021-11-17T07:13:15.000Z",
                        "lastUpdatedBy": "00000000",
                        "uid": "172983-62b91565-d2e2-4bcd-8248-4dba2e3452f0",
                    },
                    "item": [
                        {
                            "name": "Generate API Session",
                            "id": "c1bac38c-dfc9-4cc0-9c19-828cbc8543b1",
                            "protocolProfileBehavior": {"disableBodyPruning": True},
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": '{"username": "test", "password": "Test"}',
                                },
                                "url": {
                                    "raw": "https://admin:admin@the-internet.herokuapp.com/basic_auth",
                                    "host": ["https://admin:admin@the-internet.herokuapp.com/basic_auth"],
                                },
                                "description": "",
                            },
                            "response": [],
                            "uid": "10197090-c1bac38c-dfc9-4cc0-9c19-828cbc8543b1",
                        },
                        {
                            "name": "Generate API Session",
                            "id": "c1bac38c-dfc9-4cc0-9c19-828cbc8543b1",
                            "protocolProfileBehavior": {"disableBodyPruning": True},
                            "request": {
                                "method": "POST",
                                "header": [{"key": "Content-Type", "value": "application/json"}],
                                "body": {
                                    "mode": "raw",
                                    "raw": '{"username": "test", "password": "Test"}',
                                },
                                "url": {
                                    "raw": "https://admin:admin@internal.host.com",
                                    "host": ["https://admin:admin@internal.host.com"],
                                },
                                "description": "",
                            },
                            "response": [],
                            "uid": "10197090-c1bac38c-dfc9-4cc0-9c19-828cbc8543b1",
                        },
                    ],
                }
            },
        )
        temp_path = Path("/tmp/.bbot_test")
        temp_repo_path = temp_path / "test_keys"
        shutil.rmtree(temp_repo_path, ignore_errors=True)
        subprocess.run(["git", "init", "test_keys"], cwd=temp_path)
        with open(temp_repo_path / "keys.txt", "w") as f:
            f.write(self.file_content)
        subprocess.run(["git", "add", "."], cwd=temp_repo_path)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name='BBOT Test'",
                "-c",
                "user.email='bbot@blacklanternsecurity.com'",
                "commit",
                "-m",
                "Initial commit",
            ],
            check=True,
            cwd=temp_repo_path,
        )

        old_filter_event = module_test.scan.modules["git_clone"].filter_event

        def new_filter_event(event):
            event.data["url"] = event.data["url"].replace(
                "https://github.com/blacklanternsecurity", f"file://{temp_path}"
            )
            return old_filter_event(event)

        module_test.monkeypatch.setattr(module_test.scan.modules["git_clone"], "filter_event", new_filter_event)

    def check(self, module_test, events):
        vuln_events = [
            e
            for e in events
            if e.type == "VULNERABILITY"
            and (
                e.data["host"] == "hub.docker.com"
                or e.data["host"] == "github.com"
                or e.data["host"] == "www.postman.com"
            )
            and "Verified Secret Found." in e.data["description"]
            and "Raw result: [https://admin:admin@the-internet.herokuapp.com]" in e.data["description"]
            and "RawV2 result: [https://admin:admin@the-internet.herokuapp.com/basic_auth]" in e.data["description"]
        ]
        # Trufflehog should find 4 verifiable secrets, 1 from the github, 1 from the workflow log, 1 from the docker image and 1 from the postman.
        assert 4 == len(vuln_events), "Failed to find secret in events"
        github_repo_event = [e for e in vuln_events if "test_keys" in e.data["description"]][0].parent
        folder = Path(github_repo_event.data["path"])
        assert folder.is_dir(), "Destination folder doesn't exist"
        with open(folder / "keys.txt") as f:
            content = f.read()
            assert content == self.file_content, "File content doesn't match"
        filesystem_events = [e.parent for e in vuln_events]
        assert len(filesystem_events) == 4
        assert all([e.type == "FILESYSTEM" for e in filesystem_events])
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/git_repos/.bbot_test/test_keys") and Path(e.data["path"]).is_dir()
            ]
        ), "Test keys repo dir does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/workflow_logs/blacklanternsecurity/bbot/test.txt")
                and Path(e.data["path"]).is_file()
            ]
        ), "Workflow log file does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/docker_images/blacklanternsecurity_helloworld_latest.tar")
                and Path(e.data["path"]).is_file()
            ]
        ), "Docker image file does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith(
                    "/postman_workspaces/BlackLanternSecurity BBOT [Public]/3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b.zip"
                )
                and Path(e.data["path"]).is_file()
            ]
        ), "Failed to find blacklanternsecurity postman workspace"


class TestTrufflehog_NonVerified(TestTrufflehog):
    config_overrides = {"modules": {"trufflehog": {"only_verified": False}, "postman_download": {"api_key": "asdf"}}}

    def check(self, module_test, events):
        finding_events = [
            e
            for e in events
            if e.type == e.type == "FINDING"
            and (
                e.data["host"] == "hub.docker.com"
                or e.data["host"] == "github.com"
                or e.data["host"] == "www.postman.com"
            )
            and "Potential Secret Found." in e.data["description"]
            and "Raw result: [https://admin:admin@internal.host.com]" in e.data["description"]
        ]
        # Trufflehog should find 4 unverifiable secrets, 1 from the github, 1 from the workflow log, 1 from the docker image and 1 from the postman.
        assert 4 == len(finding_events), "Failed to find secret in events"
        github_repo_event = [e for e in finding_events if "test_keys" in e.data["description"]][0].parent
        folder = Path(github_repo_event.data["path"])
        assert folder.is_dir(), "Destination folder doesn't exist"
        with open(folder / "keys.txt") as f:
            content = f.read()
            assert content == self.file_content, "File content doesn't match"
        filesystem_events = [e.parent for e in finding_events]
        assert len(filesystem_events) == 4
        assert all([e.type == "FILESYSTEM" for e in filesystem_events])
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/git_repos/.bbot_test/test_keys") and Path(e.data["path"]).is_dir()
            ]
        ), "Test keys repo dir does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/workflow_logs/blacklanternsecurity/bbot/test.txt")
                and Path(e.data["path"]).is_file()
            ]
        ), "Workflow log file does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith("/docker_images/blacklanternsecurity_helloworld_latest.tar")
                and Path(e.data["path"]).is_file()
            ]
        ), "Docker image file does not exist"
        assert 1 == len(
            [
                e
                for e in filesystem_events
                if e.data["path"].endswith(
                    "/postman_workspaces/BlackLanternSecurity BBOT [Public]/3a7e4bdc-7ff7-4dd4-8eaa-61ddce1c3d1b.zip"
                )
                and Path(e.data["path"]).is_file()
            ]
        ), "Failed to find blacklanternsecurity postman workspace"
