import io
import base64
import shutil
import tarfile
import subprocess
from pathlib import Path

from .base import ModuleTestBase
from bbot.test.bbot_fixtures import bbot_test_dir


class TestGit_Clone(ModuleTestBase):
    config_overrides = {
        "modules": {"git_clone": {"api_key": "asdf", "output_folder": str(bbot_test_dir / "test_git_files")}}
    }
    modules_overrides = ["github_org", "speculate", "git_clone"]

    file_content = "https://admin:admin@the-internet.herokuapp.com/basic_auth"

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

    async def setup_after_prep(self, module_test):
        temp_path = Path("/tmp/.bbot_test")
        shutil.rmtree(temp_path / "test_keys", ignore_errors=True)
        subprocess.run(["git", "init", "test_keys"], cwd=temp_path)
        temp_repo_path = temp_path / "test_keys"
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
        filesystem_events = [
            e
            for e in events
            if e.type == "FILESYSTEM"
            and "git_repos/.bbot_test/test_keys" in e.data["path"]
            and "git" in e.tags
            and e.scope_distance == 1
        ]
        assert 1 == len(filesystem_events), "Failed to git clone CODE_REPOSITORY"
        # make sure the binary blob isn't here
        assert not any("blob" in e.data for e in [e for e in events if e.type == "FILESYSTEM"])
        filesystem_event = filesystem_events[0]
        folder = Path(filesystem_event.data["path"])
        assert folder.is_dir(), "Destination folder doesn't exist"
        with open(folder / "keys.txt") as f:
            content = f.read()
            assert content == self.file_content, "File content doesn't match"


class TestGit_CloneWithBlob(TestGit_Clone):
    config_overrides = {"folder_blobs": True}

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        assert len(filesystem_events) == 1
        assert all("blob" in e.data for e in filesystem_events)
        filesystem_event = filesystem_events[0]
        blob = filesystem_event.data["blob"]
        tar_bytes = base64.b64decode(blob)
        tar_stream = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
            assert "test_keys/keys.txt" in tar.getnames()
