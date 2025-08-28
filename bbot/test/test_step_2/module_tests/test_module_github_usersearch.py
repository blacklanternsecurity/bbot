from .base import ModuleTestBase


class TestGithub_Usersearch(ModuleTestBase):
    config_overrides = {"modules": {"github_usersearch": {"api_key": "asdf"}}}
    query_1 = """query search_users {
            search(query: "blacklanternsecurity.com", type: USER, first: 100, after: "") {
                userCount
                pageInfo {
                    hasNextPage
                    endCursor
                }
                edges {
                    node {
                        ... on User {
                          login
                          # bio Commented out as user can add arbritrary domains to their bio
                          email # Email is verified by github
                          websiteUrl # Website is not verified by github
                        }
                    }
                }
            }
        }"""
    query_2 = """query search_users {
            search(query: "blacklanternsecurity.com", type: USER, first: 100, after: "Y3Vyc29yOjUz") {
                userCount
                pageInfo {
                    hasNextPage
                    endCursor
                }
                edges {
                    node {
                        ... on User {
                          login
                          # bio Commented out as user can add arbritrary domains to their bio
                          email # Email is verified by github
                          websiteUrl # Website is not verified by github
                        }
                    }
                }
            }
        }"""

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(url="https://api.github.com/zen")
        module_test.httpx_mock.add_response(
            url="https://api.github.com/graphql",
            match_headers={"Authorization": "token asdf"},
            match_json={"query": self.query_1},
            json={
                "data": {
                    "search": {
                        "userCount": 2,
                        "pageInfo": {"hasNextPage": True, "endCursor": "Y3Vyc29yOjUz"},
                        "edges": [
                            {
                                "node": {
                                    "login": "user_one",
                                    "email": "test@blacklanternsecurity.com",
                                    "websiteUrl": None,
                                }
                            },
                            {"node": {"login": "user_two", "email": None, "websiteUrl": None}},
                        ],
                    }
                }
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.github.com/graphql",
            match_headers={"Authorization": "token asdf"},
            match_json={"query": self.query_2},
            json={
                "data": {
                    "search": {
                        "userCount": 1,
                        "pageInfo": {"hasNextPage": False, "endCursor": "Y3Vyc29yOjU"},
                        "edges": [
                            {
                                "node": {
                                    "login": "user_three",
                                    "email": None,
                                    "websiteUrl": "https://blog.blacklanternsecurity.com",
                                }
                            }
                        ],
                    }
                }
            },
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "user_one"
                and str(e.module) == "github_usersearch"
                and "github-org-member" in e.tags
                and e.scope_distance == 1
            ]
        ), "Failed to find user_one github"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "test@blacklanternsecurity.com"
                and str(e.module) == "github_usersearch"
            ]
        ), "Failed to find email address for user_one"
        assert 0 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "user_two"
                and str(e.module) == "github_usersearch"
                and "github-org-member" in e.tags
                and e.scope_distance == 1
            ]
        ), "user_two should not be in scope due to no email or website"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "github"
                and e.data["profile_name"] == "user_three"
                and str(e.module) == "github_usersearch"
                and "github-org-member" in e.tags
                and e.scope_distance == 1
            ]
        ), "Failed to find user_three github"
