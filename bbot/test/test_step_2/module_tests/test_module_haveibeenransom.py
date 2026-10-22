from .base import ModuleTestBase

base_url = "https://haveibeenransom.com/api/metadata/domain/blacklanternsecurity.com"
auth_header = {"Authorization": "Bearer deadbeef"}


def leak(id_source, post_title, group_name, leak_type, website="", discovered="2025-03-04 10:11:12.123456"):
    return {
        "id_source": id_source,
        "post_title": post_title,
        "group_name": group_name,
        "leak_type": leak_type,
        "website": website,
        "discovered": discovered,
    }


class TestHaveIBeenRansom(ModuleTestBase):
    modules_overrides = ["haveibeenransom"]
    config_overrides = {"modules": {"haveibeenransom": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=base_url,
            match_headers=auth_header,
            json={
                "sources": [
                    leak(
                        "101", "Black Lantern Security", "akira", "ransomware_leak", website="blacklanternsecurity.com"
                    ),
                    leak("db-7", "blacklanternsecurity.com customers", "𝐃𝐁𝐬  𝐁𝐚𝐜𝐤𝐮𝐩", "traditional_breach"),
                ],
                "page": 1,
                "has_next": True,
            },
        )
        # leaks without metadata are left out of a page, so a page can be empty and still have a next page
        module_test.blasthttp_mock.add_response(
            url=f"{base_url}/2", match_headers=auth_header, json={"sources": [], "page": 2, "has_next": True}
        )
        # a leak indexed while paging is repeated at the top of a later page
        module_test.blasthttp_mock.add_response(
            url=f"{base_url}/3",
            match_headers=auth_header,
            json={
                "sources": [
                    leak("101", "Black Lantern Security", "akira", "ransomware_leak"),
                    leak("102", "", "play", "ransomware_leak", website="shop.blacklanternsecurity.com"),
                ],
                "page": 3,
                "has_next": False,
            },
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        descriptions = sorted(e.data["description"] for e in findings)
        assert descriptions == [
            "Data breach: blacklanternsecurity.com customers (source: DBs Backup), discovered 2025-03-04",
            "Ransomware leak-site post: Black Lantern Security (source: akira), discovered 2025-03-04",
            "Ransomware leak-site post: shop.blacklanternsecurity.com (source: play), discovered 2025-03-04",
        ], descriptions
        for e in findings:
            assert e.data["host"] == "blacklanternsecurity.com"
            assert e.parent.type == "DNS_NAME" and e.parent.data == "blacklanternsecurity.com"
            if e.data["name"] == "Ransomware Leak":
                assert e.data["severity"] == "MEDIUM"
            else:
                assert e.data["name"] == "Data Breach" and e.data["severity"] == "LOW"


class TestHaveIBeenRansomMaxPages(TestHaveIBeenRansom):
    config_overrides = {"modules": {"haveibeenransom": {"api_key": "deadbeef", "max_pages": 1}}}

    def check(self, module_test, events):
        descriptions = sorted(e.data["description"] for e in events if e.type == "FINDING")
        # only the first page is requested
        assert len(descriptions) == 2, descriptions
        assert not any("play" in d for d in descriptions)
        log = open(module_test.scan.home / "debug.log").read()
        assert "has more results in Have I Been Ransomed? than max_pages=1 allows" in log


class TestHaveIBeenRansomDocsShape(TestHaveIBeenRansom):
    async def setup_before_prep(self, module_test):
        # the shape shown in the API docs
        module_test.blasthttp_mock.add_response(
            url=base_url,
            match_headers=auth_header,
            json={
                "success": True,
                "results": [leak("201", "Black Lantern Security", "lockbit3", "ransomware_leak")],
                "pagination": {"current_page": 1, "total_pages": 1, "has_next": False},
            },
        )

    def check(self, module_test, events):
        descriptions = [e.data["description"] for e in events if e.type == "FINDING"]
        assert descriptions == [
            "Ransomware leak-site post: Black Lantern Security (source: lockbit3), discovered 2025-03-04"
        ], descriptions


class TestHaveIBeenRansomError(TestHaveIBeenRansom):
    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=base_url, match_headers=auth_header, status_code=401, json={"error": "Invalid token"}
        )

    def check(self, module_test, events):
        assert not any(e.type == "FINDING" for e in events)
        log = open(module_test.scan.home / "debug.log").read()
        assert "Error querying Have I Been Ransomed? for blacklanternsecurity.com (status code 401)" in log
