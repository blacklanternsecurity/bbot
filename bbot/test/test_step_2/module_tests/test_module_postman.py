from .base import ModuleTestBase


class TestPostman(ModuleTestBase):
    modules_overrides = ["postman", "speculate"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {"blacklanternsecurity.com": {"A": ["127.0.0.99"]}, "github.com": {"A": ["127.0.0.99"]}}
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/ws/proxy",
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
                    }
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

    def check(self, module_test, events):
        assert len(events) == 5
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
                if e.type == "CODE_REPOSITORY"
                and "postman" in e.tags
                and e.data["url"] == "https://www.postman.com/blacklanternsecurity/bbot-public"
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity postman workspace"
