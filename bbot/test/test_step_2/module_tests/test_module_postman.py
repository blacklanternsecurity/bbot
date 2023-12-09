from .base import ModuleTestBase


class TestPostman(ModuleTestBase):
    config_overrides = {
        "modules": {"postman": {"api_key": "asdf"}},
        "omit_event_types": [],
        "scope_report_distance": 1,
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/ws/proxy",
            json={
                "data": {
                    "workspace": [
                        {
                            "score": 348.87827,
                            "normalizedScore": None,
                            "document": {
                                "isPublisherVerified": False,
                                "publisherType": "user",
                                "watcherCount": 1,
                                "curatedInList": [],
                                "apiCount": 0,
                                "creatorId": "19863351",
                                "description": "",
                                "forkCount": 0,
                                "isblacklisted": "False",
                                "createdAt": "2022-03-15T08:08:47",
                                "publisherId": "19863351",
                                "publisherHandle": "joint-operations-cosmonaut-61183650",
                                "publisherLogo": "",
                                "isPublic": True,
                                "id": "58d3317b-7c43-49a8-9484-5e3b42c62a25",
                                "categories": [],
                                "universaltags": "",
                                "slug": "testapi",
                                "views": 655,
                                "updatedAt": "2022-03-15T08:08:47",
                                "summary": "",
                                "entityType": "workspace",
                                "visibilityStatus": "public",
                                "tags": [],
                                "isBlacklisted": False,
                                "forkLabel": "",
                                "isPrivateNetworkEntity": False,
                                "publisherName": "Guypech",
                                "isDomainNonTrivial": False,
                                "name": "TestAPI",
                                "dependencyCount": 3,
                                "collectionCount": 2,
                                "privateNetworkMeta": "",
                                "warehouse__updated_at": "2023-12-04 03:00:00",
                                "privateNetworkFolders": [],
                                "documentType": "workspace",
                            },
                        },
                    ],
                    "collection": [],
                    "request": [],
                    "api": [],
                    "flow": [],
                    "team": [],
                },
                "meta": {
                    "queryText": "vulnweb.com",
                    "total": {
                        "collection": 2,
                        "request": 105,
                        "workspace": 0,
                        "api": 0,
                        "team": 0,
                        "user": 0,
                        "flow": 0,
                        "apiDefinition": 0,
                        "privateNetworkFolder": 0,
                    },
                    "state": "AQ4",
                    "spellCorrection": {
                        "count": {
                            "all": 107,
                            "workspace": 0,
                            "api": 0,
                            "team": 0,
                            "collection": 2,
                            "flow": 0,
                            "request": 105,
                        },
                        "correctedQueryText": None,
                    },
                    "featureFlags": {
                        "enabledPublicResultCuration": True,
                        "boostByPopularity": True,
                        "reRankPostNormalization": True,
                    },
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/workspace/58d3317b-7c43-49a8-9484-5e3b42c62a25",
            json={
                "model_id": "58d3317b-7c43-49a8-9484-5e3b42c62a25",
                "meta": {"model": "workspace", "action": "find"},
                "data": {
                    "id": "58d3317b-7c43-49a8-9484-5e3b42c62a25",
                    "name": "TestAPI",
                    "description": None,
                    "summary": "",
                    "createdBy": "19863351",
                    "updatedBy": "19863351",
                    "team": None,
                    "createdAt": "2022-03-15T08:08:47.000Z",
                    "updatedAt": "2022-03-15T08:08:47.000Z",
                    "visibilityStatus": "public",
                    "profileInfo": {
                        "slug": "testapi",
                        "profileType": "user",
                        "profileId": "19863351",
                        "publicHandle": "https://www.postman.com/joint-operations-cosmonaut-61183650",
                        "publicImageURL": "https://res.cloudinary.com/postman/image/upload/t_user_profile_300/v1/user/default-2",
                        "publicName": "Guypech",
                        "isVerified": False,
                    },
                    "user": "19863351",
                    "type": "personal",
                    "dependencies": {
                        "collections": [
                            "19863351-a0cbf84c-7cca-4db7-a3dc-2c58c929af69",
                            "19863351-9b276682-45a7-4f82-bbe7-eff8ed0316fc",
                        ],
                        "globals": ["49d301eb-2f27-4021-8b90-5ce7942dfaf8"],
                    },
                    "members": {"users": {"19863351": {"id": "19863351"}}},
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/collection/19863351-a0cbf84c-7cca-4db7-a3dc-2c58c929af69",
            json={
                "model_id": "a0cbf84c-7cca-4db7-a3dc-2c58c929af69",
                "meta": {
                    "model": "collection",
                    "populate": False,
                    "changeset": False,
                    "action": "find",
                    "favorite": False,
                },
                "data": {
                    "owner": "19863351",
                    "lastUpdatedBy": "19863351",
                    "lastRevision": 24003664197,
                    "team": None,
                    "id": "a0cbf84c-7cca-4db7-a3dc-2c58c929af69",
                    "name": "rest.vulnweb.com (Basic Authentication)",
                    "description": None,
                    "variables": None,
                    "auth": {
                        "type": "basic",
                        "basic": [
                            {"key": "password", "value": "123456", "type": "string"},
                            {"key": "username", "value": "admin", "type": "string"},
                        ],
                    },
                    "events": [
                        {
                            "listen": "prerequest",
                            "script": {
                                "id": "15de99b6-ac31-4a98-a009-704149f0102e",
                                "type": "text/javascript",
                                "exec": [""],
                            },
                        },
                        {
                            "listen": "test",
                            "script": {
                                "id": "dd6437b0-2a4f-44e9-a4f5-e72fc7714dd7",
                                "type": "text/javascript",
                                "exec": [""],
                            },
                        },
                    ],
                    "remote_id": "0",
                    "remoteLink": None,
                    "folders_order": [
                        "077fba92-ddc6-42ed-a2b8-903a2126e43c",
                        "725ad3a1-1c38-420b-8532-1222245c2f04",
                        "2dcc7c45-18f8-47ca-8aa2-618afd7f502e",
                    ],
                    "order": ["933c9652-4a3a-4c64-a1f2-a641f859dbfe"],
                    "createdAt": "2022-03-15T09:02:24.000Z",
                    "updatedAt": "2022-03-15T09:02:25.000Z",
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/request/19863351-b821d8fa-fecf-4c46-bee9-8c555fcd9a9f",
            json={
                "model_id": "ca6302b4-f157-4a8f-bebc-c4bc16148bde",
                "meta": {"model": "request", "populate": False, "changeset": False, "action": "find"},
                "data": {
                    "owner": "23500452",
                    "lastUpdatedBy": "23500452",
                    "lastRevision": 27990084357,
                    "folder": "109642a4-a152-49ef-97bd-b648d9b62438",
                    "collection": "f214d635-d0e0-40e7-b7c6-01684346444f",
                    "id": "ca6302b4-f157-4a8f-bebc-c4bc16148bde",
                    "name": "createEmployee",
                    "dataMode": "raw",
                    "data": None,
                    "auth": None,
                    "events": None,
                    "rawModeData": '{\r\n  "email": "dustin@gmail.com",\r\n  "first_name": "Dustin",\r\n  "last_name": "Henderson",\r\n  "work_start_date": "2022-07-22", \r\n  "send_email": "True",\r\n  "date_of_birth": "1994-05-20",\r\n  "gender": "Male",\r\n  "marital_status": "Married",\r\n  "nationality": "Canadian",\r\n  "country": "CA",\r\n  "state": "Quebec",\r\n  "post_code": "G0H",\r\n  "street_first": "ABC",\r\n  "street_second": "XYZ",\r\n  "city": "Montreal",\r\n  "position_title":"staff"\r\n}',
                    "descriptionFormat": None,
                    "description": None,
                    "variables": None,
                    "headers": "Accept: application/json\nX-Auth-Token: 898e56c53fc72149ca5cfdb9ed00d496cb62a5dc28a4f32781504114e3ab34ff6ab8d08649a44986\n",
                    "method": "POST",
                    "pathVariables": {},
                    "url": "https://njclabs.sage.hr/api/employees",
                    "preRequestScript": None,
                    "tests": None,
                    "currentHelper": None,
                    "helperAttributes": None,
                    "queryParams": [],
                    "headerData": [
                        {
                            "key": "Accept",
                            "value": "application/json",
                            "description": None,
                            "type": "text",
                            "enabled": True,
                        },
                        {
                            "key": "X-Auth-Token",
                            "value": "898e56c53fc72149ca5cfdb9ed00d496cb62a5dc28a4f32781504114e3ab34ff6ab8d08649a44986",
                            "description": None,
                            "type": "text",
                            "enabled": True,
                        },
                    ],
                    "pathVariableData": [],
                    "protocolProfileBehavior": {"disableBodyPruning": True},
                    "dataDisabled": False,
                    "responses_order": [],
                    "createdAt": "2022-11-30T15:11:24.000Z",
                    "updatedAt": "2022-11-30T16:52:57.000Z",
                    "dataOptions": {"raw": {"language": "json"}},
                },
            },
        )

    def check(self, module_test, events):
        assert any(
            e.data
            == "https://raw.githubusercontent.com/projectdiscovery/nuclei/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go"
            for e in events
        ), "Failed to detect URL"
