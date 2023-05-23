from .base import ModuleTestBase


class TestBuiltWith(ModuleTestBase):
    config_overrides = {"modules": {"builtwith": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://api.builtwith.com/v20/api.json?KEY=asdf&LOOKUP=blacklanternsecurity.com&NOMETA=yes&NOATTR=yes&HIDETEXT=yes&HIDEDL=yes",
            json={
                "Results": [
                    {
                        "Result": {
                            "IsDB": "True",
                            "Spend": 734,
                            "Paths": [
                                {
                                    "Technologies": [
                                        {
                                            "Name": "nginx",
                                            "Tag": "Web Server",
                                            "FirstDetected": 1533510000000,
                                            "LastDetected": 1559516400000,
                                            "IsPremium": "no",
                                        },
                                        {
                                            "Parent": "nginx",
                                            "Name": "Nginx 1.14",
                                            "Tag": "Web Server",
                                            "FirstDetected": 1555542000000,
                                            "LastDetected": 1559516400000,
                                            "IsPremium": "no",
                                        },
                                        {
                                            "Name": "Domain Not Resolving",
                                            "Tag": "hosting",
                                            "FirstDetected": 1613894400000,
                                            "LastDetected": 1633244400000,
                                            "IsPremium": "no",
                                        },
                                    ],
                                    "FirstIndexed": 1533510000000,
                                    "LastIndexed": 1633244400000,
                                    "Domain": "blacklanternsecurity.com",
                                    "Url": "",
                                    "SubDomain": "asdf",
                                }
                            ],
                        },
                        "Meta": {
                            "Majestic": 0,
                            "Umbrella": 0,
                            "Vertical": "",
                            "Social": None,
                            "CompanyName": None,
                            "Telephones": None,
                            "Emails": [],
                            "City": None,
                            "State": None,
                            "Postcode": None,
                            "Country": "US",
                            "Names": None,
                            "ARank": 6249242,
                            "QRank": -1,
                        },
                        "Attributes": {
                            "Employees": 0,
                            "MJRank": 0,
                            "MJTLDRank": 0,
                            "RefSN": 0,
                            "RefIP": 0,
                            "Followers": 0,
                            "Sitemap": 0,
                            "GTMTags": 0,
                            "QubitTags": 0,
                            "TealiumTags": 0,
                            "AdobeTags": 0,
                            "CDimensions": 0,
                            "CGoals": 0,
                            "CMetrics": 0,
                            "ProductCount": 0,
                        },
                        "FirstIndexed": 1389481200000,
                        "LastIndexed": 1684220400000,
                        "Lookup": "blacklanternsecurity.com",
                        "SalesRevenue": 0,
                    }
                ],
                "Errors": [],
                "Trust": None,
            },
        )
        module_test.httpx_mock.add_response(
            url=f"https://api.builtwith.com/redirect1/api.json?KEY=asdf&LOOKUP=blacklanternsecurity.com",
            json={
                "Lookup": "blacklanternsecurity.com",
                "Inbound": [
                    {
                        "Domain": "blacklanternsecurity.github.io",
                        "FirstDetected": 1564354800000,
                        "LastDetected": 1683783431121,
                    }
                ],
                "Outbound": None,
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "blacklanternsecurity.github.io" for e in events), "Failed to detect redirect"
