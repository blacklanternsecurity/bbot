from .base import ModuleTestBase


class TestGithub(ModuleTestBase):
    config_overrides = {"modules": {"github": {"api_key": "asdf"}}, "omit_event_types": [], "scope_report_distance": 1}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(url="https://api.github.com/zen")
        module_test.httpx_mock.add_response(
            url="https://api.github.com/search/code?per_page=100&type=Code&q=blacklanternsecurity.com&page=1",
            json={
                "total_count": 214,
                "incomplete_results": False,
                "items": [
                    {
                        "name": "main.go",
                        "path": "v2/cmd/cve-annotate/main.go",
                        "sha": "4aa7c9ec68acb4c603d4b9163bf7ed42de1939fe",
                        "url": "https://api.github.com/repositories/252813491/contents/v2/cmd/cve-annotate/main.go?ref=06f242e5fce3439b7418877676810cbf57934875",
                        "git_url": "https://api.github.com/repositories/252813491/git/blobs/4aa7c9ec68acb4c603d4b9163bf7ed42de1939fe",
                        "html_url": "https://github.com/projectdiscovery/nuclei/blob/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go",
                        "repository": {
                            "id": 252813491,
                            "node_id": "MDEwOlJlcG9zaXRvcnkyNTI4MTM0OTE=",
                            "name": "nuclei",
                            "full_name": "projectdiscovery/nuclei",
                            "private": False,
                            "owner": {
                                "login": "projectdiscovery",
                                "id": 50994705,
                                "node_id": "MDEyOk9yZ2FuaXphdGlvbjUwOTk0NzA1",
                                "avatar_url": "https://avatars.githubusercontent.com/u/50994705?v=4",
                                "gravatar_id": "",
                                "url": "https://api.github.com/users/projectdiscovery",
                                "html_url": "https://github.com/projectdiscovery",
                                "followers_url": "https://api.github.com/users/projectdiscovery/followers",
                                "following_url": "https://api.github.com/users/projectdiscovery/following{/other_user}",
                                "gists_url": "https://api.github.com/users/projectdiscovery/gists{/gist_id}",
                                "starred_url": "https://api.github.com/users/projectdiscovery/starred{/owner}{/repo}",
                                "subscriptions_url": "https://api.github.com/users/projectdiscovery/subscriptions",
                                "organizations_url": "https://api.github.com/users/projectdiscovery/orgs",
                                "repos_url": "https://api.github.com/users/projectdiscovery/repos",
                                "events_url": "https://api.github.com/users/projectdiscovery/events{/privacy}",
                                "received_events_url": "https://api.github.com/users/projectdiscovery/received_events",
                                "type": "Organization",
                                "site_admin": False,
                            },
                            "html_url": "https://github.com/projectdiscovery/nuclei",
                            "description": "Fast and customizable vulnerability scanner based on simple YAML based DSL.",
                            "fork": False,
                            "url": "https://api.github.com/repos/projectdiscovery/nuclei",
                            "forks_url": "https://api.github.com/repos/projectdiscovery/nuclei/forks",
                            "keys_url": "https://api.github.com/repos/projectdiscovery/nuclei/keys{/key_id}",
                            "collaborators_url": "https://api.github.com/repos/projectdiscovery/nuclei/collaborators{/collaborator}",
                            "teams_url": "https://api.github.com/repos/projectdiscovery/nuclei/teams",
                            "hooks_url": "https://api.github.com/repos/projectdiscovery/nuclei/hooks",
                            "issue_events_url": "https://api.github.com/repos/projectdiscovery/nuclei/issues/events{/number}",
                            "events_url": "https://api.github.com/repos/projectdiscovery/nuclei/events",
                            "assignees_url": "https://api.github.com/repos/projectdiscovery/nuclei/assignees{/user}",
                            "branches_url": "https://api.github.com/repos/projectdiscovery/nuclei/branches{/branch}",
                            "tags_url": "https://api.github.com/repos/projectdiscovery/nuclei/tags",
                            "blobs_url": "https://api.github.com/repos/projectdiscovery/nuclei/git/blobs{/sha}",
                            "git_tags_url": "https://api.github.com/repos/projectdiscovery/nuclei/git/tags{/sha}",
                            "git_refs_url": "https://api.github.com/repos/projectdiscovery/nuclei/git/refs{/sha}",
                            "trees_url": "https://api.github.com/repos/projectdiscovery/nuclei/git/trees{/sha}",
                            "statuses_url": "https://api.github.com/repos/projectdiscovery/nuclei/statuses/{sha}",
                            "languages_url": "https://api.github.com/repos/projectdiscovery/nuclei/languages",
                            "stargazers_url": "https://api.github.com/repos/projectdiscovery/nuclei/stargazers",
                            "contributors_url": "https://api.github.com/repos/projectdiscovery/nuclei/contributors",
                            "subscribers_url": "https://api.github.com/repos/projectdiscovery/nuclei/subscribers",
                            "subscription_url": "https://api.github.com/repos/projectdiscovery/nuclei/subscription",
                            "commits_url": "https://api.github.com/repos/projectdiscovery/nuclei/commits{/sha}",
                            "git_commits_url": "https://api.github.com/repos/projectdiscovery/nuclei/git/commits{/sha}",
                            "comments_url": "https://api.github.com/repos/projectdiscovery/nuclei/comments{/number}",
                            "issue_comment_url": "https://api.github.com/repos/projectdiscovery/nuclei/issues/comments{/number}",
                            "contents_url": "https://api.github.com/repos/projectdiscovery/nuclei/contents/{+path}",
                            "compare_url": "https://api.github.com/repos/projectdiscovery/nuclei/compare/{base}...{head}",
                            "merges_url": "https://api.github.com/repos/projectdiscovery/nuclei/merges",
                            "archive_url": "https://api.github.com/repos/projectdiscovery/nuclei/{archive_format}{/ref}",
                            "downloads_url": "https://api.github.com/repos/projectdiscovery/nuclei/downloads",
                            "issues_url": "https://api.github.com/repos/projectdiscovery/nuclei/issues{/number}",
                            "pulls_url": "https://api.github.com/repos/projectdiscovery/nuclei/pulls{/number}",
                            "milestones_url": "https://api.github.com/repos/projectdiscovery/nuclei/milestones{/number}",
                            "notifications_url": "https://api.github.com/repos/projectdiscovery/nuclei/notifications{?since,all,participating}",
                            "labels_url": "https://api.github.com/repos/projectdiscovery/nuclei/labels{/name}",
                            "releases_url": "https://api.github.com/repos/projectdiscovery/nuclei/releases{/id}",
                            "deployments_url": "https://api.github.com/repos/projectdiscovery/nuclei/deployments",
                        },
                        "score": 1.0,
                    }
                ],
            },
        )

    def check(self, module_test, events):
        assert any(
            e.data
            == "https://raw.githubusercontent.com/projectdiscovery/nuclei/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go"
            for e in events
        ), "Failed to detect URL"
