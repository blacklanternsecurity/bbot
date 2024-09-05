import io
import zipfile
from pathlib import Path

from .base import ModuleTestBase


class TestGithub_Workflows(ModuleTestBase):
    config_overrides = {"modules": {"github_org": {"api_key": "asdf"}}}
    modules_overrides = ["github_workflows", "github_org", "speculate"]

    data = io.BytesIO()
    with zipfile.ZipFile(data, mode="w", compression=zipfile.ZIP_DEFLATED) as zipfile:
        zipfile.writestr("test.txt", "This is some test data")
        zipfile.writestr("test2.txt", "This is some more test data")
        zipfile.writestr("folder/test3.txt", "This is yet more test data")
    data.seek(0)
    zip_content = data.getvalue()

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(url="https://api.github.com/zen")
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
                    "html_url": "https://github.com/blacklanternsecurity/bbot",
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
                }
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
        module_test.httpx_mock.add_response(
            url="https://productionresultssa10.blob.core.windows.net/actions-results/7beb304e-f42c-4830-a027-4f5dec53107d/workflow-job-run-3a559e2a-952e-58d2-b8db-2e604a9266d7/logs/steps/step-logs-0e34a19a-18b0-4208-b27a-f8c031db2d17.txt?rsct=text%2Fplain&se=2024-04-26T16%3A25%3A39Z&sig=a%2FiN8dOw0e3tiBQZAfr80veI8OYChb9edJ1eFY136B4%3D&sp=r&spr=https&sr=b&st=2024-04-26T16%3A15%3A34Z&sv=2021-12-02",
            content=self.zip_content,
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/repos/blacklanternsecurity/bbot/actions/runs/8839360698/artifacts",
            json={
                "total_count": 1,
                "artifacts": [
                    {
                        "id": 1829832535,
                        "node_id": "MDg6QXJ0aWZhY3QxODI5ODMyNTM1",
                        "name": "build.tar.gz",
                        "size_in_bytes": 245770648,
                        "url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/artifacts/1829832535",
                        "archive_download_url": "https://api.github.com/repos/blacklanternsecurity/bbot/actions/artifacts/1829832535/zip",
                        "expired": False,
                        "created_at": "2024-08-19T22:32:17Z",
                        "updated_at": "2024-08-19T22:32:18Z",
                        "expires_at": "2024-09-02T22:21:59Z",
                        "workflow_run": {
                            "id": 10461468466,
                            "repository_id": 89290483,
                            "head_repository_id": 799444840,
                            "head_branch": "not-a-real-branch",
                            "head_sha": "1eeb5354ab7b1e4141b8a6473846e2a5ea0dd2c6",
                        },
                    }
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/repos/blacklanternsecurity/bbot/actions/artifacts/1829832535/zip",
            headers={
                "location": "https://pipelinesghubeus22.actions.githubusercontent.com/uYHz4cw2WwYcB2EU57uoCs3MaEDiz8veiVlAtReP3xevBriD1h/_apis/pipelines/1/runs/214601/signedartifactscontent?artifactName=build.tar.gz&urlExpires=2024-08-20T14%3A41%3A41.8000556Z&urlSigningMethod=HMACV2&urlSignature=OOBxLx4eE5A8uHjxOIvQtn3cLFQOBW927mg0hcTHO6U%3D"
            },
            status_code=302,
        )
        module_test.httpx_mock.add_response(
            url="https://pipelinesghubeus22.actions.githubusercontent.com/uYHz4cw2WwYcB2EU57uoCs3MaEDiz8veiVlAtReP3xevBriD1h/_apis/pipelines/1/runs/214601/signedartifactscontent?artifactName=build.tar.gz&urlExpires=2024-08-20T14%3A41%3A41.8000556Z&urlSigningMethod=HMACV2&urlSignature=OOBxLx4eE5A8uHjxOIvQtn3cLFQOBW927mg0hcTHO6U%3D",
            content=self.zip_content,
        )

    def check(self, module_test, events):
        assert len(events) == 8
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
                and e.data["url"] == "https://github.com/blacklanternsecurity"
                and str(e.module) == "github_org"
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity github"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "https://github.com/blacklanternsecurity/bbot"
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity github repo"
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        assert 3 == len(filesystem_events), filesystem_events
        for filesystem_event in filesystem_events:
            file = Path(filesystem_event.data["path"])
            assert file.is_file(), "Destination file does not exist"
