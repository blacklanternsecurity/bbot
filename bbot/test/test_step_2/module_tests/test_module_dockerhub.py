from .base import ModuleTestBase


class TestDockerhub(ModuleTestBase):
    modules_overrides = ["dockerhub", "speculate"]

    async def setup_before_prep(self, module_test):
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
                    {
                        "name": "testimage",
                        "namespace": "blacklanternsecurity",
                        "repository_type": "image",
                        "status": 1,
                        "status_description": "active",
                        "description": "",
                        "is_private": False,
                        "star_count": 0,
                        "pull_count": 1,
                        "last_updated": "2022-01-10T20:16:46.170738Z",
                        "date_registered": "2022-01-07T13:28:59.756641Z",
                        "affiliation": "",
                        "media_types": ["application/vnd.docker.container.image.v1+json"],
                        "content_types": ["image"],
                        "categories": [],
                    },
                ],
            },
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "docker"
                and e.data["profile_name"] == "blacklanternsecurity"
            ]
        ), "Failed to find blacklanternsecurity docker"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and e.data["url"] == "https://hub.docker.com/r/blacklanternsecurity/helloworld"
                and "docker" in e.tags
            ]
        ), "Failed to find helloworld docker repo"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and e.data["url"] == "https://hub.docker.com/r/blacklanternsecurity/testimage"
                and "docker" in e.tags
            ]
        ), "Failed to find testimage docker repo"
