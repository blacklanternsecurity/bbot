from .base import ModuleTestBase

hibr_url = "https://haveibeenransom.com/api/metadata/domain/blacklanternsecurity.com"
hibr_auth = {"Authorization": "Bearer hibr-deadbeef"}
breachhouse_url = "https://breach.house/api/v1/search?q=blacklanternsecurity.com&limit=25"
breachhouse_auth = {"Authorization": "Bearer bh-deadbeef"}


def leak(id_source, post_title, group_name, leak_type, website="", discovered="2025-03-04 10:11:12.123456"):
    return {
        "id_source": id_source,
        "post_title": post_title,
        "group_name": group_name,
        "leak_type": leak_type,
        "website": website,
        "discovered": discovered,
    }


def record(id, post_title, group_name, website="", discovered="2025-03-04 10:11:12.123456"):
    return {
        "id": id,
        "post_title": post_title,
        "group_name": group_name,
        "website": website,
        "discovered": discovered,
    }


def add_hibr_pages(module_test):
    module_test.blasthttp_mock.add_response(
        url=hibr_url,
        match_headers=hibr_auth,
        json={
            "sources": [
                leak("101", "Black Lantern Security", "akira", "ransomware_leak", website="blacklanternsecurity.com"),
                leak("db-7", "blacklanternsecurity.com customers", "𝐃𝐁𝐬  𝐁𝐚𝐜𝐤𝐮𝐩", "traditional_breach"),
            ],
            "page": 1,
            "has_next": True,
        },
    )
    # leaks without metadata are left out of a page, so a page can be empty and still have a next page
    module_test.blasthttp_mock.add_response(
        url=f"{hibr_url}/2", match_headers=hibr_auth, json={"sources": [], "page": 2, "has_next": True}
    )
    # a leak indexed while paging is repeated at the top of a later page
    module_test.blasthttp_mock.add_response(
        url=f"{hibr_url}/3",
        match_headers=hibr_auth,
        json={
            "sources": [
                leak("101", "Black Lantern Security", "akira", "ransomware_leak"),
                leak("102", "", "play", "ransomware_leak", website="shop.blacklanternsecurity.com"),
            ],
            "page": 3,
            "has_next": False,
        },
    )


def add_breachhouse_search(module_test, url=breachhouse_url):
    module_test.blasthttp_mock.add_response(
        url=url,
        match_headers=breachhouse_auth,
        json={
            # the same victim Have I Been Ransomed? returns
            "ransomware": {
                "results": [
                    record(12345, "Black Lantern Security", "akira", website="blacklanternsecurity.com"),
                    record(12346, "Black Lantern Security", "qilin", website="blacklanternsecurity.com"),
                ],
                "total": 2,
            },
            # a text match on another company's record
            "breaches": {
                "results": [record(77, "Evil Corp vendors", "evilforum", website="evilcorp.com")],
                "total": 1,
            },
            "leads": {"results": [record(456, "", "initaccess", website="vpn.blacklanternsecurity.com")], "total": 1},
            "stealers": {"results": [record(321, "blacklanternsecurity.com", "lumma")], "total": 1},
        },
    )


class TestDarkEye(ModuleTestBase):
    modules_overrides = ["darkeye"]
    config_overrides = {
        "modules": {"darkeye": {"haveibeenransom_api_key": "hibr-deadbeef", "breachhouse_api_key": "bh-deadbeef"}}
    }

    async def setup_before_prep(self, module_test):
        add_hibr_pages(module_test)
        add_breachhouse_search(module_test)

    def findings(self, events):
        return {e.data["description"]: e.data for e in events if e.type == "FINDING"}

    def check(self, module_test, events):
        findings = self.findings(events)
        assert sorted(findings) == [
            "DarkEye access lead (Breach House): vpn.blacklanternsecurity.com (source: initaccess), discovered 2025-03-04",
            "DarkEye data breach (Breach House): Evil Corp vendors (source: evilforum), discovered 2025-03-04",
            "DarkEye data breach (Have I Been Ransomed?): blacklanternsecurity.com customers (source: DBs Backup), discovered 2025-03-04",
            "DarkEye ransomware leak-site post (Breach House): Black Lantern Security (source: qilin), discovered 2025-03-04",
            "DarkEye ransomware leak-site post (Have I Been Ransomed?): Black Lantern Security (source: akira), discovered 2025-03-04",
            "DarkEye ransomware leak-site post (Have I Been Ransomed?): shop.blacklanternsecurity.com (source: play), discovered 2025-03-04",
            "DarkEye stealer log (Breach House): blacklanternsecurity.com (source: lumma), discovered 2025-03-04",
        ], sorted(findings)
        expected = {
            "Ransomware Leak": "MEDIUM",
            "Data Breach": "LOW",
            "Access Lead": "MEDIUM",
            "Stealer Log": "MEDIUM",
        }
        for description, data in findings.items():
            assert data["host"] == "blacklanternsecurity.com"
            assert data["severity"] == expected[data["name"]]
            # the Breach House text match on another company's website, and the stealer log without a website
            low = "Evil Corp" in description or "lumma" in description
            assert data["confidence"] == ("LOW" if low else "MEDIUM"), description
        for e in events:
            if e.type == "FINDING":
                assert e.parent.type == "DNS_NAME" and e.parent.data == "blacklanternsecurity.com"


class TestDarkEyeLimits(TestDarkEye):
    config_overrides = {
        "modules": {
            "darkeye": {
                "haveibeenransom_api_key": "hibr-deadbeef",
                "breachhouse_api_key": "bh-deadbeef",
                "max_pages": 1,
                "limit": 1,
            }
        }
    }

    async def setup_before_prep(self, module_test):
        add_hibr_pages(module_test)
        module_test.blasthttp_mock.add_response(
            url=breachhouse_url.replace("limit=25", "limit=1"),
            match_headers=breachhouse_auth,
            json={
                "ransomware": {
                    "results": [record(12346, "Black Lantern Security", "qilin", website="blacklanternsecurity.com")],
                    "total": 3,
                },
                "breaches": {"results": [], "total": 0},
                "leads": {"results": [], "total": 0},
                "stealers": {"results": [], "total": 0},
            },
        )

    def check(self, module_test, events):
        findings = self.findings(events)
        # only the first Have I Been Ransomed? page is requested
        assert not any("play" in d for d in findings)
        assert len([d for d in findings if "Have I Been Ransomed?" in d]) == 2
        assert len([d for d in findings if "Breach House" in d]) == 1
        log = open(module_test.scan.home / "debug.log").read()
        assert "has more results in Have I Been Ransomed? than max_pages=1 allows" in log
        assert "has more results in Breach House than limit=1 allows" in log


class TestDarkEyeHIBROnly(TestDarkEye):
    config_overrides = {"modules": {"darkeye": {"haveibeenransom_api_key": "hibr-deadbeef"}}}

    def check(self, module_test, events):
        findings = self.findings(events)
        assert len(findings) == 3, findings
        assert all("(Have I Been Ransomed?)" in d for d in findings)


class TestDarkEyeBreachHouseOnly(TestDarkEye):
    config_overrides = {"modules": {"darkeye": {"breachhouse_api_key": "bh-deadbeef"}}}

    def check(self, module_test, events):
        findings = self.findings(events)
        # without the Have I Been Ransomed? key, the akira victim comes from Breach House
        assert len(findings) == 5, findings
        assert all("(Breach House)" in d for d in findings)
        assert any("(source: akira)" in d for d in findings)


class TestDarkEyeHIBRDocsShape(TestDarkEyeHIBROnly):
    async def setup_before_prep(self, module_test):
        # the shape shown in the Have I Been Ransomed? API docs
        module_test.blasthttp_mock.add_response(
            url=hibr_url,
            match_headers=hibr_auth,
            json={
                "success": True,
                "results": [leak("201", "Black Lantern Security", "lockbit3", "ransomware_leak")],
                "pagination": {"current_page": 1, "total_pages": 1, "has_next": False},
            },
        )

    def check(self, module_test, events):
        assert list(self.findings(events)) == [
            "DarkEye ransomware leak-site post (Have I Been Ransomed?): Black Lantern Security (source: lockbit3), discovered 2025-03-04"
        ]


class TestDarkEyeError(TestDarkEye):
    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=hibr_url, match_headers=hibr_auth, status_code=401, json={"error": "Invalid token"}
        )
        add_breachhouse_search(module_test)

    def check(self, module_test, events):
        findings = self.findings(events)
        # a failed product doesn't stop the other one
        assert len(findings) == 5 and all("(Breach House)" in d for d in findings), findings
        log = open(module_test.scan.home / "debug.log").read()
        assert "Error querying Have I Been Ransomed? for blacklanternsecurity.com (status code 401)" in log


class TestDarkEyeNoKey(TestDarkEye):
    config_overrides = {}

    async def setup_before_prep(self, module_test):
        pass

    def check(self, module_test, events):
        # setup soft-fails without a key, so the module isn't loaded and makes no requests
        assert "darkeye" not in module_test.scan.modules
        assert not any(e.type == "FINDING" for e in events)
