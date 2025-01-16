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
            match_content=b'{"service": "search", "method": "POST", "path": "/search-all", "body": {"queryIndices": ["collaboration.workspace"], "queryText": "blacklanternsecurity", "size": 25, "from": 0, "clientTraceId": "", "requestOrigin": "srp", "mergeEntities": "true", "nonNestedRequests": "true", "domain": "public"}}',
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
        assert all(e.type == "FILESYSTEM" for e in filesystem_events)
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
            and "Possible Secret Found." in e.data["description"]
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
        assert all(e.type == "FILESYSTEM" for e in filesystem_events)
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


class TestTrufflehog_HTTPResponse(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "trufflehog"]
    config_overrides = {"modules": {"trufflehog": {"only_verified": False}}}

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "https://admin:admin@internal.host.com"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "FINDING" for e in events)


class TestTrufflehog_RAWText(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/test.pdf"]
    modules_overrides = ["httpx", "trufflehog", "filedownload", "extractous"]
    config_overrides = {"modules": {"trufflehog": {"only_verified": False}}}

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/test.pdf"}
        respond_args = {
            "response_data": b"%PDF-1.4\n%\xc7\xec\x8f\xa2\n%%Invocation: path/gs -P- -dSAFER -dCompatibilityLevel=1.4 -dWriteXRefStm=false -dWriteObjStms=false -q -P- -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sstdout=? -sOutputFile=? -P- -dSAFER -dCompatibilityLevel=1.4 -dWriteXRefStm=false -dWriteObjStms=false -\n5 0 obj\n<</Length 6 0 R/Filter /FlateDecode>>\nstream\nx\x9c-\x8c\xb1\x0e\x82@\x10D\xfb\xfd\x8a-\xa1\xe0\xd8\xe5@\xe1*c\xb4\xb1\xd3lba,\xc8\x81\x82\xf1@\xe4\xfe?\x02\x92If\x92\x97\x99\x19\x90\x14#\xcdZ\xd3: |\xc2\x00\xbcP\\\xc3:\xdc\x0b\xc4\x97\xed\x0c\xe4\x01\xff2\xe36\xc5\x9c6Jk\x8d\xe2\xe0\x16\\\xeb\n\x0f\xb5E\xce\x913\x93\x15F3&\x94\xa4a\x94fD\x01\x87w9M7\xc5z3Q\x8cx\xd9'(\x15\x04\x8d\xf7\x9f\xd1\xc4qY\xb9\xb63\x8b\xef\xda\xce\xd7\xdf\xae|\xab\xa6\x1f\xbd\xb2\xbd\x0b\xe5\x05G\x81\xf3\xa4\x1f~q-\xc7endstream\nendobj\n6 0 obj\n155\nendobj\n4 0 obj\n<</Type/Page/MediaBox [0 0 595 842]\n/Rotate 0/Parent 3 0 R\n/Resources<</ProcSet[/PDF /Text]\n/Font 11 0 R\n>>\n/Contents 5 0 R\n>>\nendobj\n3 0 obj\n<< /Type /Pages /Kids [\n4 0 R\n] /Count 1\n>>\nendobj\n1 0 obj\n<</Type /Catalog /Pages 3 0 R\n/Metadata 14 0 R\n>>\nendobj\n11 0 obj\n<</R9\n9 0 R/R7\n7 0 R>>\nendobj\n9 0 obj\n<</BaseFont/YTNPVC+Courier/FontDescriptor 10 0 R/Type/Font\n/FirstChar 46/LastChar 116/Widths[ 600 600\n0 0 0 0 0 0 0 0 0 0 600 0 0 0 0 0\n600 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n0 600 0 600 600 600 0 0 600 600 0 0 600 600 600 600\n600 0 600 600 600]\n/Encoding/WinAnsiEncoding/Subtype/Type1>>\nendobj\n7 0 obj\n<</BaseFont/NXCWXT+Courier-Bold/FontDescriptor 8 0 R/Type/Font\n/FirstChar 32/LastChar 101/Widths[\n600 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n600 600 600 600 600 600 0 0 600 600 600 0 0 0 0 0\n0 0 0 0 600 0 0 0 0 0 0 0 0 0 0 0\n0 0 0 0 0 0 0 600 0 0 0 0 0 0 0 0\n0 0 0 600 600 600]\n/Encoding/WinAnsiEncoding/Subtype/Type1>>\nendobj\n10 0 obj\n<</Type/FontDescriptor/FontName/YTNPVC+Courier/FontBBox[0 -182 599 665]/Flags 33\n/Ascent 665\n/CapHeight 665\n/Descent -182\n/ItalicAngle 0\n/StemV 89\n/AvgWidth 600\n/MaxWidth 600\n/MissingWidth 600\n/XHeight 433\n/CharSet(/a/at/c/colon/d/e/h/i/l/m/n/o/p/period/r/s/slash/t)/FontFile3 12 0 R>>\nendobj\n12 0 obj\n<</Filter/FlateDecode\n/Subtype/Type1C/Length 1794>>stream\nx\x9c\x9dT{TS\xf7\x1d\xbf\x91ps\x8f\xa0\xb2\xdc\x06\x1f\xe8\xbdX[|\xa0\x85\xaa\xad\xa7\xf4\x14P\x1eG9\x05\x9c\xa2\x08\xb4\xee@\x88\xc83\x08\x04\x84\x80\x84@B\xd3\x1f84!@\x12\x08\xe0\x8b\x97S\xe9\xc4U\xf4\x06\xb5\x15\xdd:5\xc8&j=\xb2\xad:'T9\xeb\xce\xbe\xb7\xe7\xban\xbf\x80\x16\xdb\xd3\xed\x8f\x9d\x93?n\xee\xe3\xf3\xfb~\x1e\xdf\x8f\x88\x10\xcf D\"\x11\x15\xa6T\xe5\xa5+\xf2\\\xd7\xabx\x1f\x11\xbfp\x06\xbf\xc8\r\tQ\xfc\xd8\xb7\xab\xdcy\xc6\x93\xa8\xf1\x14!O7\xe4)n_H\x19\xa4\xd0\xfb3\xa8\x9d\x03\xc5^\x84X$Z\x17\x9dd]\xb6mK\xfcr\x7f\xff\x95a\xca\xdc\xe2\xbc\xf4\xb4\xdd\x05\xbe\xab\x03\xdf\\\xeb\x9bR\xec\xfb\xfc\x89o\xb8\"?=-\xc7\xd7\x0f_\x14*\xb2\x94\xb9\xd9\x8a\x9c\x82\x98\xf4\xec\x14U\xbeo\xb42G\xe9\xbby\xab\xef\x16E\x9a*+9\xef\x87w\xa7\x11\xff\xbf3\x08\x82\x90\xe6(s\xf3\xf2\x0b\x92\xe5\xa9\x8a\xdd\xe9Y\xd9o\x04\x04\x85\x12D,\xb1\x99\xf89\xb1\x95\x88#\xb6\x11\x1b\x88p\"\x82\x88$6\x11QD4\x11C\xcc!\xbc\x08\x1fb1Acq\x081\xa1'\x06E\x1bE}3>\x9cq\xc1m\x93[\x9fx\x89\xb8P\x0c\xee\x91\xee\x95\xe4\xab\xe4zRIvJ\xd6\xf3\xe3\xb3\xf9q\xc4\xc1}N:\x08\xee\xf1\x0eht\xcc\xa5Ga=\xbfN\x16D\xaa**KJ\xcc\xdaV\x96\x1e\xe9\x10\x9crR\xa5\xd1\xaaK\x1a\xf0\x7f\x98G\xb6\x9aM6\xab\xc6T\xc8\xcaAG^\xf9\xe3a\xcb\x15t\x02\xb5\xe8\xda\x8a\x0f\x155\x14\xa0\\J\xa8PJ\xa6\xdf\x17\x91\xf6\x86\xe7\xef\xe7\xc0G\xe4\xed\x88\xc1\x00\x86\x1e\x8dAi\xc5\xdb\xb7Rx\x025\x07O9\xd15\x07\xfc\xdb\xe1\x06\x9f\xf1\x112a\xc1k\xcb\x05Z\xf0\xfaf)x\x83\xf7\xdf\x9f\x80\x14\xe6\xbc6!\xd0\xacn\x87\xec\x9b\xbb\xa1\xcb\xfc\xdf\r\xf6\xf3\x0b\x1a\x19\x7f|\xf7\xf6\x13\x16\x03\x08Q\x1c,\xe6`\x90\xdb\xc5Im0\x1f\x13\xf9\x1a\x13y\x04+0\x11\xbf\x97\x88|u\xeeYu\"I?*t\x8d\xe6\xba\x03\xdb\xc8\xb6)**\x96~\x18\x00\x05\xe4\xa7[.\xee\x19F\x14H\xc7\x1f\x81\x07K/\x00O\xff\x87\xc2+\xeb\x93\xf2cv0t\"\x04\x1f\x97=\xb9\x15\x11\xb8:$\xdc\x7fE\xc8\xd0\x83\xbf\xdc\xba\xf97vJC'\x97\xc2I\xe1\x17\xf8\xdc\x1b`\xc4\xe7\n\xb3\xc8\xc2r\xadZ\xddP\xd1\xca\xde\x10\x9c\x81\xf8_E\xe9\x94\x1e\xceI=,\xe5\xf5E\xac\xb0\x01RI:p\x1c\x88\x9e\xb6>\x1f;j\xd6\x1e\xca7V\xed7\x98\x10e1\x9b\xad\xf5:\xd3^\x0b\x9b\xdb\xae2e\xa1x\xf4\xc1\x9e5\xefM\xe9\xb5\xdb\x0e\xdfq\xe9v)x\\\x82\xc3\x97\xe6\xd2\xef\xc3\n\x98)\xb3j\xcc\xa5%ZM!\x13$)4ilV\x93\xd9\xce\xd0=Y\xa7\x06\xd4W|`\xe6\xfdKwN\x14\xfd*\xb3\x95\xcdh\xdbe\x8e>\xb0\xa6^_\xa3j,6k,\xa8\x89\xea\x1d\xe8\xb89|>7\xa5\x8e\xa9-6j-\x88\xb2\x99\xcc\xad\xecu\t\xbd\xb0UkV\x97UT\x94\x1a0\xd2\x91\xf4\x9d\x8d\xdb|\xfcB\x137f4gu\x16\xb3\x1d\xc5\x1dU\x7f\xa8\xba\xa8;\xa2;Rzx\x9fU\x85\n\xa9\xc4\xf7\xd3\xde~g\xe3\xf1\xd3\xcc\x94\xad\x7f\xe2D\xe0\x8bM\x8d\xc3\x82\x80X\xd2\xaa\xad/\xc1\x03\x161\x828\x12\xe7c\xd2\x966\xac\x8e\x99\x0c\xf9m\xc2\xd7g/\x99\x9b\xfb\x99\x93M\xd6Fd\xa1\x9a4\xe62}\xf5\xc7:-\x93\xaa\x8aT\xc7!jSJ\xe7Y\x16L\x90!q9f\xd3\x18U\xec\x94\x14\x1c\xbc\xc5\x81\x07'\xc5\xf9\xe9w\xc4\xc3\xfc\xb9t\x1e\xbf\xda{b:\xa3ti\"\x98\xc8\xe1\xf0\x01\x7fE\xd4\xbe\xbdqL\x99\xbe\xaa\x12\x95SefMc\xdd\xfe\x9a_62\x9f5\x9f6v#\xca\xd9\x9f\xbd\x93\x8d\x96\xc4Z\xf2\xf6\xefD\x94\xe0\xbd6v5Kk\x83\xbf\xd8>v\xe3b\xdb\xc0U,\xc0eqTl|A$\xa26&w\xf5\x7f\xee\xfc\xe4\xe9\x99~}e\x0f\xfb\"\xc2\xd8\x90;.\xff\xf9]\xbcL&\xef\xdan\xdb\x8ca\x16-_)\xcc\x17dc\x01\xe0s\xed\xf7-'\x06\xd8N\xbb\xa5\x19K\xde\xa81\xef\xab\xd4\x1b\xb4Z&\xe1\xc3\x98\x820D-\x0euN\xfccx\xe8\x9f\xf7\xae)\x12\x0e\xb0\xb5E\xc6\xca)\x1f\xec\xec\x03\t\x1d\x88}()\xa9\xc4\xde\xbe }\x7f\x92\xf4\xe7\x0ehvQ>\xc7\xd7\xf1Oq\xd6\xbfO\xf69a\x17\xb9s0\xb6+\x1c\x8f0g\xd9R\xc1K\xf0z\xe2\x07\xb3\x87\xaev_>\x83\x15\t\x9d\x90|\xafO\")\x14\xc1}\x9c\xeb\xd0e,\xdd\xe3\x1f\x1c\x8c\xa3=2>vk\xe4\xf1s\x17\xd7r\xb0\x90\x13\xf1\xed\x10/3J\x0eJ\xe0\x95\xa5\x8f\x85\x05\xc2\xbc\xd7W\t\xb3\x84y z\x1d\xd8q\xf0\xe8?\xe5\xb2LWm\xd0U2\xf2\xec0U,Z\x82\xde\xfb]\xd9\x18\xc5\x89m\xf7n^\xf8+z\x88\x86\xe3\xacA\xd4\x8b\xc6\xc1\xd3\x8b\xc0\xc3\x01M8\x1e!?\x9a\xfd\x99\xe1Gu\xd3\xf0|G\xe5PM\x1e\xed\xb4\xb5\x1c\xa8\xeb8t\xb4\xfe\x14\xeaEvW\xe9\xec\xc5\xa5\xa3\xc4\xa5#\x97Lo\xf6\x0f\xbe\xaa\"\xefE\x0e\xae\x8cM)\xda\x9e\xc4\xbcX\xd7\x07\xe0.\x85\x83\xce\x84\xc9\xa6\xb8\xe3\xda\xd8w\xa6\xab\x02\xdc\x05\xa7\x100=\x12|7\r\x87\xef\xd3\x13\x06\xfe\xba,Bpw\x92\x93p\xbc\x01\x939\x8a\x99\xdc\xc1L\x84uS\xc3\xbb\xb2\rn\xcf\x0c\xff\x03\xc7\xf5\xb1k\x95\xa5\x07@\xbc\x83\x835\xae\x9f\xab\x81g\xe2q\xde}\xa9\xb8n\xe0\x06\xce!\xe9Q\x17\x0en\x94\x16W\xa7b\x1c\xabm\xb2\xb8\xbeT\x82\x91<1\xd0\xd9~\x1cQ]\xc72w\xb3\xc2\xf5\xbb\xd3\xf6\xe6L>\xech\xefAT\xcf\xb1\xectV\x18\xba+y\xa9\x8f\x0f\x91W\x12\xce\xc7\xa4d\x97$\xc9\x99\xfc3\x99\xad\xc9\x88\xa2G\xe5(G\x9d\xa5pyUj\x17A?x\xc9\x923\xb3SS\xbb\xb3N\xb3f\xf2tw\xe7'\xbd\x99\x9d\xc9\xae\xdc\xf3\xeao\xc5\xb2\xba\xfa\x9aZTG5\x96\x9b\xcb\xca\xab\xf4\xa5U\x8c\xf0\xe5\xbfB\xaa+?\xaeF\xfa\xf9\xfb\x1a4M\r\x07\xeb,\x07\x99I0~\xd1O\xe1u\xf5N\xe2i\xe0\xec\x7f;'\xe6<\x04p\xbc''z\xea\x18u\x80\x97\xc3\x8d\x7f\x13^\x95\xf5\xe2%767T\x99\xca\xf7\xb3`\x97<\nw\xbe!Po\x0bn\xc2JFX#Aa-\xd1'w\x9c\x8c\xffM\xfeUD\xdd\x1e\xe99\x8eW\xaeT\xa77T\xeb\xd9=\xf9\x19\x9aD\x94\x842l{Nf\xf7\xa9/\xa2\xcb\x14\x04J@z\xf5\xab?\x7fq\xf6\x83(F.Y\xf2QX,ZGm\x18\x8c\xbbg6\xd5\xd461\xe7\xc5j\x83\x1eU *N\xd1\xfd\xe9\x85\x81_\x0f\xd5\xb0\xb3\xd5V\xfe-+x7\x1ck$\x1d39\x8f>\x93\xa7g\x9f\xd1s\x16A\xfc\x07\xbe\x9e\x12\xf0\nendstream\nendobj\n8 0 obj\n<</Type/FontDescriptor/FontName/NXCWXT+Courier-Bold/FontBBox[-14 -15 617 617]/Flags 131105\n/Ascent 617\n/CapHeight 566\n/Descent -15\n/ItalicAngle 0\n/StemV 92\n/AvgWidth 600\n/MaxWidth 600\n/MissingWidth 600\n/XHeight 437\n/CharSet(/D/W/c/colon/d/e/eight/five/four/nine/one/space/three/two/zero)/FontFile3 13 0 R>>\nendobj\n13 0 obj\n<</Filter/FlateDecode\n/Subtype/Type1C/Length 1758>>stream\nx\x9c\x9d\x93{PSg\x1a\xc6O\x80\x9c\x9c\xad\xb4\"\xd9S\xd4\xb6Iv\xba\xabh\x91\x11\xa4\xad\xbbu\xb7\xd3B\xcb\xb6\x16G\xc1\x16P\xa0\x18\x03$\x84\\ AHBX\x92p1\xbc\x04\xb9$\xe1\x12 @@B@.\xca\x1dA\xb7\x8a\x80\x8e\x8b\xbb\x9d\xae\xb3\xf62\xbb\xba[;[hw\xc3\xd4\xef\x8cGg\xf6$\xe8t\xf7\xdf\xfd\xeb\x9cy\xbfs\xde\xf7\xf9~\xcf\xf3\xb2\xb0\xa0\x00\x8c\xc5b=\x1b\xab(,\x90d\x15\xecy[\x91'\xf2\x15\"\xa8\x17X\xd4\x8b\x01\xd4K\x81\xfa\x12\xea1\xf5\x98M\xf1\x82\xb1\x9a`\x16\x04\x07BpP\xc7\x8b\x9c\x0b\xa1\xc8\xb3\x05\xc1f\xa4\r\xc1\x82X\xac\xd7\xdfOi\x0e\xff01y\xd7+\xafD\xc4*\x94\x9a\x02I\x8eX-\x88\xde\x1b\x15#\x10j\x04ON\x04qY*I\x8e\\\xb0\x83y9\x95\x95\xa7P\xca\xb2\xe4\xeaC\x12\x99\xb0P%HP\xc8\x15\x82\xc3I\x02\x9f\x80\xff-\xfd\xd8\xee\xff\x1b\x80a\xd8\xe6\xb8\x93\xa2\xac\xe4\xbdQ\xd1\xfbb^\x15\xec\xff\xe5\xaf0\xec\x17X\x1c\xf6\x0e\xf6.\xb6\x1f\xdb\x82\x85b\\\xec\xa7\x18\x89=\x8f\xb1\xb0m\xd8v\xec\x05,\x84\x81\x82\x05aE\x18\xc5r\x07\x04\x04X\x03\x1e\x04&\x05^\tJ\x0bZ`\xc7\xb3\xdfg/\xe1\xb1\xb8\x86Z}\x8eZ\x05/z\xe8eQ\x89\x08\x0b\xfc\xa3\x97\xcc\xaaV\x17C\x1eh\xad\xbaf\xa3\xad\xbc\xf5\xb4\x0b\x08\x94\x89\xa3\xe8*\x14\xf8\xef\x1a\x14ALr\x00\xed\xa19h\x13\xbd\xd3L\xd0b\\\t\xa6jC\x85\xce`\xd0\x82\xd6\xf7W\x8b\xd1Z\xde`\xee\xaa&\x10F?$\xd1\xc3\x1f8\xf7\xcf\xac\xbck\t'28\x10\x91p$\xfc\x0c\xc1\x8c,\xf1\xa2j/k\x8e\x99H\x8dQ89\xad\xeb\xcc),3\x15\x97\xf3\xb2\xda\x8fY\x8f\x02A\xef\x11\xec\xa6\xf9\x87;S\xc6D\xfc\xb9\xb4\xebEk\xf0\x19\xdc\xb0\x8f9';\xbb{\xe1,\xd1\xa7r\xc9J\rU&\x03\xefd\xae\xd4\xf8\x06\xf3='q\xf4\xcf_,^\xfafb\xc8\xa4\xeb\xe17\x95\xd7\x9bjuu\x85\xb5\x15\x8d\xe5V\x93\xa3\xa2\x05\xda\xc0\xd1hon\xb4Yl\xd0\xeb\x13P\xea\x8dr\xa2\x15o\xa8\x1bah\x02aa\xdc)j\x80\xfa\x9e\xa4\x83\xf1\xfc\xa7\xf7\xd1\x81\x06\xb4\x8d%-\x06{\xb9\xed\xf4Y \x9a~\x86\x8b\xdc\xa9\xad\x89\xf0\x1bH,J\xcbL\xcbT%\xc1\x07p\xd0\x954\x939\x93y\xb5\xe86,\xc0\x85\xa6\x8b\x1e\x82[,C\xc1\x1c\x17\xd8-\xd6:\x87\xcd\xd6\x06\xed\xe009\xf4\xb6\xb2\x06\xa3E\x01\xc4\xefp\xba\x1e\x95\x90\xb3\xe0)\xeb\xcbw\x15\xb6HAFp\xa7\xde:\x9c\x1a\x93\x9e\xdb\xd4\xa3\xe4\xa9\xba\xf5\x1e\x18\x00O\x8b\xc7\xd5}\xb6w\xc0>\x0b\x1b\xc0n\xdf\xff\x0bc\xd2<\xdaO\x8eq\xd0v:p\x8d\x8e\xa0w\xd1\xecp\x9a\xa4\xc3P@$\x8a\xfe\xd4\xdb\xe6\x9c\xe2\xf5\xd8\x9aZ\xa1\x93p\x17v\xcb\xcb\xca\xcc\xa7KyQ\xea\xfc\xaat\xd8\x0f\xa9\xae\x82K\x84\xe5>\xe9\x98^\x18X\x81\x15\xb8*mK\xf7u\x06'\x95\xe0e\xa1\xcb\xc8F~M\xdb\xd8\x88\xc0\x17)a\x7f][\x07\x9c\xdd\xc6\x08o\xd5\xdb\x9f\x08\xa7\xc3\x9e\xb21\x1a4>\xaf\x1b\x19\xaf\xed&\xbb\xb9\x17\x88\x8bx.m\x8cE\x1f\xb3i\x0c\x8f\xa5?\xceEF\xf6\x04\xeeC`\xfb\x11A+\x83\xa0\xd1\xf0\xa4\x93\x12\xca\x99NZ\x83Q\x07E\xa0ph\xfb\xab\x96\x1f\t\xb7\xa2gpF\x91\xdeK\xfd\xda\xcb\xba\xc38s\xca\x17\x90v\xf4\x1d\t\xf7\xe4wR\xe7s\x86\x8e\xb7\x1f\x81#p\\\x93#NM\x91\x1f\x80}D\x14\x07b\xdco\xcc\xa5\x0e\x8bg5\x0b\x8c\x03\xb3\xed\xc3Css\xee\xcf\xe1.A\xdf]%\xd7&\xaf\xdf\xba5\xf9\xc1.\xde\xcf9\xbb3\x0e\xc6\xc7g\xdcX\xe5m$\xfe\xae\x93\x85\xaa\x99\xf6\xe8\x01\xf5\x98\xa4e\x1f\x9d0\xe8\xf5 \xdf&\xebR\xf5\xd9jk\xea\x9c\xbc/;\xd9\x8f\xb6\xec\xe6\xe4\xffw\xbcuV\xed\xc6Rt3K\xf1\t>\xedj?\xe7\xbf\x17\xdfw1%\x10\xbb}\xf2a\x9d\x8ad\x9cz\xd9\xd7\\\xbeN\xa2f\x94\xe5\x1e\x84\xaf\x88\x07\x91_\xd0!\x87\x92\x8a\xc4B\x9eX\xa6L\x03)\xa1\xecQ\xbb\xbb\x9dM\xed\xf5<\xbb\xa7\xc6b\xb5u\xb9\x06[\xce\x03q}V\x9c\x96\xa7+\xde\x19\xc3\x17\xe6\xbc\x93H\x13Q\x15\x95[\x05\x94\xf0\x1e\x07\\fk\x85\xcd\xd0\xaa\xb5\x16\x83\x14\xb4\xba*1\xe1\xc7\x85\xbes^\xf3\x86R;\x11\xf6\xaa/\xca\xdf 7\xf5\x13R\xaa*\x94\xcb\x9d\xda!3\x7f\xcal7;M\xd3\x9a>)H\xe0T\x99ZW\x9a\xaf\xce1\xc6\xc3A\x90\xd7\xa9\x1cZ[\xa5\xa5\x14\x88<\xb5Z\x9e\xf2U.\n\xbdw\xb9yp\x8a?s\xce\xfd\t\\\x85\xc5\xec\xb9\xb8s\x04\xf7_\x8bC\xbd\xa3\xf3\xdba\xbcx\\\xea\x11\x8d$w\xc43&\x06\x86'\x1f\x91\xbb\xd4\xee\xd6\x96z\x9b\x95?0\xd8k\xfb=\x10\x7f\x18\xcf?!:)I\xe3\xfb)\xbb}\xd2X\xe8[\x9f\x8d\xc9\xd4\x1aI\xbf\x84\xd3U\x8fH\xf6\xeb\xa8G.\xe1\x14\x80\xd1l\xa8\xdc@KH\\\x9ai\x1e\xda\x8a\xcf\xf8\x99:\xf4V\xbe\xa1\xa1\xdcRXC\xb89\xe7k\xba:\x98\x8d\xf0/\x91\xa1\xde_\xa4\xb1\xe7i\x1e\x8ex(\x97\xbdA \xdf\xfbW&\xc4\x1c&3\x19>\xee*\xaa\x92D\xc7\xf0.h\xb14>M`\x9b?\x81\r~\xa3\xe8kt\x1f\x9e\xdb\xad\xf2\xd8\xcf\xd44\xb4\xf0\xc6\x9c\xd3\xcd\x1e nNd\xc4\xbf\x95.\xd9\xf1\x9e\xa2\xa1[\xc6/i6\xd5\x96\x00!/P+\x92\xee\x9f@!\xdf.t\xccL\xf1\x87G\x9d\xf3p\x85@[\xf6~M\x87\xc8\xf3*\rb_\xa06D\xbc\xb6\x8e\xf6yC\x99\xe0\x863:D\xfeG\x18w\x95z\x13-\x91W\x86\xddSp\x91\xf8>\xf2\x0e\xbd\x89\xde\x14y`g\xaa;\xf3J6\x8f\xebM\xc8\x96\xa6\x1c\xde\xfe\xf2\xdf\xe3P\x18\xda\xfa\x8f?\xad_\x93\xce'\x8c\xf0\xb8\xab4\x17\t\xc9\xa5\ti\xfa\xb1\x13\xd2\x84C\x99\x8333\xe3\x03\xcb|\xae\x97v\x04-\xcf\xe7d\x1cO\xcf\xfd\xed{i\x833\xd3\xf3\xc3\xcb>\xd6\xfa\x1fP\xe8::\xeae=\xf0\xb1\x8eC\xfd\xa4\x92f\xed{s\x07\x18\xe1t\x8d\xa1V[o\xb0\x18\x80\x90\x15\xa8e\xa2\xd9\xfcO\xff\xf9\xe5\x85\xcfW\xf8\x97\x96z?\x83\xbf\xc1-\xcdm\xe5\xb4\xe8\xe6\xa1\xc1\xd7 \x1eR\x8b\xb3E\x92\x9c\xe2T8\xca\x18|7\x1aa\xb3\xa3m\xe3\x93<\x13\xdaL\xe6g\x1c\xcb\x15\x02\x91,\x1c\xbf\xbc4<\xbcx\xe3\x9c\xf8@\xab\x7f4\xe3\xf0\xb2\x9e<\xefq\x8f\x8e\xe4\xf5\x8b\xf8\x1a<K*\xcb\xce\xf6\xc8\xce\xf3\xdb\xd1U\xa6\xde?2\x9a\xe7\xf6\xd5EyL}@6\xca\x7f\xae\xb4\x99Zs\xe0\xdeg\x10\xb6\xe9\xe6Hp\xf0\xcd\xf1\xe0g1\xec?N\xf8\xb8\xce\nendstream\nendobj\n14 0 obj\n<</Type/Metadata\n/Subtype/XML/Length 1251>>stream\n<?xpacket begin='\xef\xbb\xbf' id='W5M0MpCehiHzreSzNTczkc9d'?>\n<?adobe-xap-filters esc=\"CRLF\"?>\n<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='XMP toolkit 2.9.1-13, framework 1.6'>\n<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' xmlns:iX='http://ns.adobe.com/iX/1.0/'>\n<rdf:Description rdf:about=\"\" xmlns:pdf='http://ns.adobe.com/pdf/1.3/' pdf:Producer='GPL Ghostscript 10.03.1'/>\n<rdf:Description rdf:about=\"\" xmlns:xmp='http://ns.adobe.com/xap/1.0/'><xmp:ModifyDate>2024-12-18T15:59:31-05:00</xmp:ModifyDate>\n<xmp:CreateDate>2024-12-18T15:59:31-05:00</xmp:CreateDate>\n<xmp:CreatorTool>GNU Enscript 1.6.6</xmp:CreatorTool></rdf:Description>\n<rdf:Description rdf:about=\"\" xmlns:xapMM='http://ns.adobe.com/xap/1.0/mm/' xapMM:DocumentID='uuid:86e4e793-f59f-11fa-0000-c8d2c052bf7e'/>\n<rdf:Description rdf:about=\"\" xmlns:dc='http://purl.org/dc/elements/1.1/' dc:format='application/pdf'><dc:title><rdf:Alt><rdf:li xml:lang='x-default'>Enscript Output</rdf:li></rdf:Alt></dc:title><dc:creator><rdf:Seq><rdf:li></rdf:li></rdf:Seq></dc:creator></rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n                                                                        \n                                                                        \n<?xpacket end='w'?>\nendstream\nendobj\n2 0 obj\n<</Producer(GPL Ghostscript 10.03.1)\n/CreationDate(D:20241218155931-05'00')\n/ModDate(D:20241218155931-05'00')\n/Title(Enscript Output)\n/Author()\n/Creator(GNU Enscript 1.6.6)>>endobj\nxref\n0 15\n0000000000 65535 f \n0000000711 00000 n \n0000007145 00000 n \n0000000652 00000 n \n0000000510 00000 n \n0000000266 00000 n \n0000000491 00000 n \n0000001145 00000 n \n0000003652 00000 n \n0000000815 00000 n \n0000001471 00000 n \n0000000776 00000 n \n0000001773 00000 n \n0000003974 00000 n \n0000005817 00000 n \ntrailer\n<< /Size 15 /Root 1 0 R /Info 2 0 R\n/ID [<9BB34E42BF7AF21FE61720F4EBDFCCF8><9BB34E42BF7AF21FE61720F4EBDFCCF8>]\n>>\nstartxref\n7334\n%%EOF\n"
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        finding_events = [e for e in events if e.type == "FINDING"]
        assert len(finding_events) == 1
        assert "Possible Secret Found" in finding_events[0].data["description"]
