from .base import ModuleTestBase


class TestPostman(ModuleTestBase):
    config_overrides = {
        "omit_event_types": [],
        "scope_report_distance": 1,
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/ws/proxy",
            json={
                "data": {
                    {
                        "score": 499.22498,
                        "normalizedScore": 8.43312276976538,
                        "document": {
                            "isPublisherVerified": False,
                            "publisherType": "user",
                            "curatedInList": [],
                            "publisherId": "20346597",
                            "publisherHandle": "",
                            "publisherLogo": "",
                            "isPublic": True,
                            "customHostName": "",
                            "id": "20346597-8c1b9aba-f6ef-4f23-9f3a-8431f3567ac1",
                            "workspaces": [
                                {
                                    "visibilityStatus": "public",
                                    "name": "SageCollection",
                                    "id": "f68e0a1e-74a3-4139-bb22-48028d712814",
                                    "slug": "sagecollection",
                                }
                            ],
                            "collectionForkLabel": "",
                            "method": "POST",
                            "entityType": "request",
                            "url": "https://api.accounting.sage.com/v3.1/contact_persons",
                            "isBlacklisted": False,
                            "warehouse__updated_at_collection": "2023-12-11 02:00:00",
                            "isPrivateNetworkEntity": False,
                            "warehouse__updated_at_request": "2023-12-11 02:00:00",
                            "publisherName": "Aftab Sipahi",
                            "name": "Returns a single Contact Person that has been created.",
                            "privateNetworkMeta": "",
                            "privateNetworkFolders": [],
                            "documentType": "request",
                            "collection": {
                                "id": "20346597-d88a6492-942b-46cb-9c17-ca4aac5c8f9e",
                                "name": "Sage Accounting API - Contacts",
                                "tags": [],
                                "forkCount": 0,
                                "watcherCount": 0,
                                "views": 31,
                                "apiId": "",
                                "apiName": "",
                            },
                        },
                    },
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://www.postman.com/_api/list/collection?workspace=f68e0a1e-74a3-4139-bb22-48028d712814",
            json={
                "data": [
                    {
                        "id": "23500452-0b0b9c23-bd02-4d8c-89be-5c5548dd8454",
                        "name": "Xeropayroll",
                        "folders_order": [],
                        "order": ["029c93f7-cbdf-4629-9227-99eef840d74f"],
                        "attributes": {
                            "permissions": {
                                "userCanUpdate": False,
                                "userCanDelete": False,
                                "userCanShare": False,
                                "userCanCreateMock": False,
                                "userCanCreateMonitor": False,
                                "anybodyCanView": True,
                                "teamCanView": True,
                            },
                            "fork": None,
                            "parent": {"type": "workspace", "id": "de00a340-c5aa-4858-816f-64299ece98fd"},
                            "flags": {"isArchived": False, "isFavorite": False},
                        },
                        "folders": [],
                        "requests": [
                            {
                                "id": "23500452-029c93f7-cbdf-4629-9227-99eef840d74f",
                                "name": "New Request",
                                "method": "POST",
                                "collection": "23500452-0b0b9c23-bd02-4d8c-89be-5c5548dd8454",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            }
                        ],
                    },
                    {
                        "id": "23500452-1f619dd1-b4bb-408c-bbec-df75f55424d5",
                        "name": "Xero OAuth 2.0",
                        "folders_order": [],
                        "order": [
                            "8e4c61c0-0547-4c25-a395-c435b1e5892b",
                            "19572fa2-ae18-4419-b113-7fb786cb03be",
                            "c880274e-a9cc-4e41-a61c-666c39f09e65",
                            "12c98dc3-b0cb-4b9b-8664-b03f4b318554",
                        ],
                        "attributes": {
                            "permissions": {
                                "userCanUpdate": False,
                                "userCanDelete": False,
                                "userCanShare": False,
                                "userCanCreateMock": False,
                                "userCanCreateMonitor": False,
                                "anybodyCanView": True,
                                "teamCanView": True,
                            },
                            "fork": None,
                            "parent": {"type": "workspace", "id": "de00a340-c5aa-4858-816f-64299ece98fd"},
                            "flags": {"isArchived": False, "isFavorite": False},
                        },
                        "folders": [],
                        "requests": [
                            {
                                "id": "23500452-12c98dc3-b0cb-4b9b-8664-b03f4b318554",
                                "name": "Refresh token",
                                "method": "POST",
                                "collection": "23500452-1f619dd1-b4bb-408c-bbec-df75f55424d5",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                            {
                                "id": "23500452-19572fa2-ae18-4419-b113-7fb786cb03be",
                                "name": "Connections",
                                "method": "GET",
                                "collection": "23500452-1f619dd1-b4bb-408c-bbec-df75f55424d5",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                            {
                                "id": "23500452-8e4c61c0-0547-4c25-a395-c435b1e5892b",
                                "name": "Get started",
                                "method": "GET",
                                "collection": "23500452-1f619dd1-b4bb-408c-bbec-df75f55424d5",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                            {
                                "id": "23500452-c880274e-a9cc-4e41-a61c-666c39f09e65",
                                "name": "Invoices",
                                "method": "GET",
                                "collection": "23500452-1f619dd1-b4bb-408c-bbec-df75f55424d5",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                        ],
                    },
                    {
                        "id": "23500452-5b9d0a79-d876-4179-8c83-a67407565aed",
                        "name": "staffology",
                        "folders_order": [],
                        "order": ["5a802c60-9cab-4cde-a205-d005f0402893", "e9429383-ac36-4e9b-8ce0-4f7972bb1863"],
                        "attributes": {
                            "permissions": {
                                "userCanUpdate": False,
                                "userCanDelete": False,
                                "userCanShare": False,
                                "userCanCreateMock": False,
                                "userCanCreateMonitor": False,
                                "anybodyCanView": True,
                                "teamCanView": True,
                            },
                            "fork": None,
                            "parent": {"type": "workspace", "id": "de00a340-c5aa-4858-816f-64299ece98fd"},
                            "flags": {"isArchived": False, "isFavorite": False},
                        },
                        "folders": [],
                        "requests": [
                            {
                                "id": "23500452-5a802c60-9cab-4cde-a205-d005f0402893",
                                "name": "create employee",
                                "method": "POST",
                                "collection": "23500452-5b9d0a79-d876-4179-8c83-a67407565aed",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                            {
                                "id": "23500452-e9429383-ac36-4e9b-8ce0-4f7972bb1863",
                                "name": "Get employee",
                                "method": "GET",
                                "collection": "23500452-5b9d0a79-d876-4179-8c83-a67407565aed",
                                "folder": None,
                                "responses_order": [],
                                "responses": [],
                            },
                        ],
                    },
                    {
                        "id": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                        "name": "sageHR",
                        "folders_order": [
                            "809fc5b8-8332-4801-b0ee-6c4f1e020bc3",
                            "109642a4-a152-49ef-97bd-b648d9b62438",
                            "3d5762c5-362f-4355-a2bc-606796bb35d2",
                        ],
                        "order": [],
                        "attributes": {
                            "permissions": {
                                "userCanUpdate": False,
                                "userCanDelete": False,
                                "userCanShare": False,
                                "userCanCreateMock": False,
                                "userCanCreateMonitor": False,
                                "anybodyCanView": True,
                                "teamCanView": True,
                            },
                            "fork": None,
                            "parent": {"type": "workspace", "id": "de00a340-c5aa-4858-816f-64299ece98fd"},
                            "flags": {"isArchived": False, "isFavorite": False},
                        },
                        "folders": [
                            {
                                "id": "23500452-109642a4-a152-49ef-97bd-b648d9b62438",
                                "name": "employee",
                                "folder": None,
                                "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                "folders_order": [],
                                "order": [
                                    "ca8eff3b-c809-43db-a46c-89ab878133f6",
                                    "ca6302b4-f157-4a8f-bebc-c4bc16148bde",
                                ],
                                "folders": [],
                                "requests": [
                                    {
                                        "id": "23500452-ca6302b4-f157-4a8f-bebc-c4bc16148bde",
                                        "name": "createEmployee",
                                        "method": "POST",
                                        "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                        "folder": "23500452-109642a4-a152-49ef-97bd-b648d9b62438",
                                        "responses_order": [],
                                        "responses": [],
                                    },
                                    {
                                        "id": "23500452-ca8eff3b-c809-43db-a46c-89ab878133f6",
                                        "name": "getallEmployees",
                                        "method": "GET",
                                        "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                        "folder": "23500452-109642a4-a152-49ef-97bd-b648d9b62438",
                                        "responses_order": [],
                                        "responses": [],
                                    },
                                ],
                            },
                            {
                                "id": "23500452-3d5762c5-362f-4355-a2bc-606796bb35d2",
                                "name": "timesheet--Timeclocking",
                                "folder": None,
                                "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                "folders_order": [],
                                "order": ["f5f4ff14-3ccb-4100-be32-8277e4f7286a"],
                                "folders": [],
                                "requests": [
                                    {
                                        "id": "23500452-f5f4ff14-3ccb-4100-be32-8277e4f7286a",
                                        "name": "enter clock time",
                                        "method": "POST",
                                        "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                        "folder": "23500452-3d5762c5-362f-4355-a2bc-606796bb35d2",
                                        "responses_order": [],
                                        "responses": [],
                                    }
                                ],
                            },
                            {
                                "id": "23500452-809fc5b8-8332-4801-b0ee-6c4f1e020bc3",
                                "name": "LeaveManagement",
                                "folder": None,
                                "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                "folders_order": [],
                                "order": [
                                    "63dec2de-4215-44e7-99cc-23645c4110e9",
                                    "a9b00e60-5da1-4800-af76-fce8798a7c0c",
                                ],
                                "folders": [],
                                "requests": [
                                    {
                                        "id": "23500452-63dec2de-4215-44e7-99cc-23645c4110e9",
                                        "name": "create new timeoff request",
                                        "method": "POST",
                                        "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                        "folder": "23500452-809fc5b8-8332-4801-b0ee-6c4f1e020bc3",
                                        "responses_order": [],
                                        "responses": [],
                                    },
                                    {
                                        "id": "23500452-a9b00e60-5da1-4800-af76-fce8798a7c0c",
                                        "name": "List Timeoff Policies",
                                        "method": "GET",
                                        "collection": "23500452-f214d635-d0e0-40e7-b7c6-01684346444f",
                                        "folder": "23500452-809fc5b8-8332-4801-b0ee-6c4f1e020bc3",
                                        "responses_order": [],
                                        "responses": [],
                                    },
                                ],
                            },
                        ],
                        "requests": [],
                    },
                ]
            },
        )

    def check(self, module_test, events):
        assert any(
            e.data
            == "https://raw.githubusercontent.com/projectdiscovery/nuclei/06f242e5fce3439b7418877676810cbf57934875/v2/cmd/cve-annotate/main.go"
            for e in events
        ), "Failed to detect URL"
