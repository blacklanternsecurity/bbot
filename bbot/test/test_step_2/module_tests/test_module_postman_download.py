from .base import ModuleTestBase


class TestPostman_Download(ModuleTestBase):
    config_overrides = {"modules": {"postman_download": {"api_key": "asdf"}}}
    modules_overrides = ["postman", "postman_download", "speculate"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.getpostman.com/me",
            match_headers={"X-Api-Key": "asdf"},
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

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {"blacklanternsecurity.com": {"A": ["127.0.0.99"]}, "github.com": {"A": ["127.0.0.99"]}}
        )
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
            match_headers={"X-Api-Key": "asdf"},
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
            match_headers={"X-Api-Key": "asdf"},
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
            match_headers={"X-Api-Key": "asdf"},
            json={
                "collection": {
                    "info": {
                        "_postman_id": "62b91565-d2e2-4bcd-8248-4dba2e3452f0",
                        "name": "BBOT Public",
                        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                        "updatedAt": "2021-11-17T07:13:16.000Z",
                        "createdAt": "2021-11-17T07:13:15.000Z",
                        "lastUpdatedBy": "00000000",
                        "uid": "00000000-62b91565-d2e2-4bcd-8248-4dba2e3452f0",
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
                                "url": {"raw": "{{endpoint_url}}", "host": ["{{endpoint_url}}"]},
                                "description": "",
                            },
                            "response": [],
                            "uid": "10197090-c1bac38c-dfc9-4cc0-9c19-828cbc8543b1",
                        },
                    ],
                }
            },
        )

    def check(self, module_test, events):
        assert 1 == len(
            [e for e in events if e.type == "CODE_REPOSITORY" and "postman" in e.tags and e.scope_distance == 1]
        ), "Failed to find blacklanternsecurity postman workspace"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "FILESYSTEM"
                and "postman_workspaces/BlackLanternSecurity BBOT [Public]" in e.data["path"]
                and "postman" in e.tags
                and e.scope_distance == 1
            ]
        ), "Failed to find blacklanternsecurity postman workspace"
