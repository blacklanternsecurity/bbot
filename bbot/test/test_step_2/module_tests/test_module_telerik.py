import re
from .base import ModuleTestBase


class TestTelerik(ModuleTestBase):
    targets = ["http://127.0.0.1:8888", "http://127.0.0.1:8888/telerik.aspx"]
    modules_overrides = ["httpx", "telerik"]
    config_overrides = {"modules": {"telerik": {"exploit_RAU_crypto": True}}}

    async def setup_before_prep(self, module_test):
        # Simulate Telerik.Web.UI.WebResource.axd?type=rau detection
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.WebResource.axd", "query_string": "type=rau"}
        respond_args = {
            "response_data": '{ "message" : "RadAsyncUpload handler is registered successfully, however, it may not be accessed directly." }'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate Vulnerable Telerik.Web.UI.WebResource.axd
        vuln_data = "ATTu5i4R+ViNFYO6kst0jC11wM/1iqH+W/isjhaDjNuCI7eJ/BY5d1E9eqZK27CJCMuon9u8/hgRIM/cTlgLlv4qOYjPBjs81Y3dAZAdtIr3TXiCmZi9M09a1BYMxjvGKfVky3b7PoOppeWS/3rglTwL1e8oyqLGx2NKUH5y8Cd+kLKV2f31J1sV4I5HTDKgDmvziJp3zlDrCb0Fi9ilKH+O1cbVx6SdBop/U30FxLaB/QIbt2N1rQHREJ5Skpgo7dilPxzBaTObdBhCVyB/FiJhenS/0u3h0Mpi6+A40SylICcyyxQha7+Uh7lEJ8Ne+2eTs4WqcaaQbvIhy7oHc+D0soxRKMZRjo7Up+UWHQJJh6KtWSCxUESNSdNcxjPQZE9HqsPlldVlkeC+ehSGce5bR0Ylots6Iz1OoCgMEWwxByeG3VzgxF6XpitL61A1hFcNo9euSTnCfOWh0vrQHON7DN5LpM9xr7SoD0Dnu01hZ9NS1PHhPLyN5WS87u5qdZp/z3Sxwc3wawIdo62RNf4Iz2gAKJZnPfxrE1mRn5kBe7f6O44rcuv6lcdao/DGlwbERKwRI6/n+FxGmc7H5iEKyihIwS2XUoOgsYTx5CWCDM8CuOXTk+H5fPYp9APRPbkD1IS9I/vRmvNPwWsgv8/7DzttqdBsGxiZJfCw1uZ7KSVmbItgXPAcscNxGEMaHXyJzkAl/mlM5/t/YSejwYoSW6jFfQcLdaVx2dpIpl5UmmQjFedzKeiNqpZDCk4yzXFHX24XUODYMJDtIJK2Hz1KTZmFG+LAOJjB9QOI58hFAnytcKay+JWFrzah/IvoNZxJUtlYdxw0YEyKs/ExET7AXgYQN0S+8j2PfaMMpzDSctTqpp5XBFV4Mt718GiqVnQJtWQv2p9Xl8XXOerBthbzzAciVcB8AV2WfZ51W3e4aX4kcyT/sCJhm7NR5WrNG5mX/ns0TTnGnzlPYhJcbu8uMFjMGDpXuhVyroJ7wmZucaIvesg0h5Y9cMEFviqsdy15vjMzFh+v9uO9Vicf6n9Z9JGSpWKE8wer2JU5b53Zw0cTfulAAffLWXnzOnfu&6R/cGaqQeHVAzdJ9wTFOyCsrMSTtqcjLe8AHwiPckPDUwecnJyNlkDYwDQpxGYQ9hs6YxhupK310sbCbtXB4H6Dz5rGNL40nkkyo4j2clmRr08jtFsPQ0RpE5BGsulPT3l0MxyAvPFMs8bMybUyAP+9RB9LoHE3Xo8BqDadX3HQakpPfGtiDMp+wxkWRgaNpCnXeY1QewWTF6z/duLzbu6CT6s+H4HgBHrOLTpemC2PvP2bDm0ySPHLdpapLYxU8nIYjLKIyYJgwv9S9jNckIVpcGVTWVul7CauCKxAB2mMnM9jJi8zfFwKajT5d2d9XfpkiVMrdlmikSB/ehyX1wQ=="
        expect_args = {
            "method": "POST",
            "uri": "/Telerik.Web.UI.WebResource.axd",
            "query_string": "type=rau",
            "data": vuln_data,
        }
        respond_args = {
            "response_data": '{"fileInfo":{"FileName":"RAU_crypto.bypass","ContentType":"text/html","ContentLength":5,"DateJson":"2019-01-02T03:04:05.067Z","Index":0}, "metaData":"CS8S/Z0J/b2982DRxDin0BBslA7fI0cWMuWlPu4W3FkE4tKaVoIEiAOtVlJ6D+0RQsfu8ox6gvMYxceQ0LtWyTkQBaIUa8LgLQg05DMaQuufHNx0YQ2ACi5neqDBvduj2MGiSGC0hNKzSWsHystZGUfFPLTZuJXYnff+WXurecuRzSI7d4Q1aj0bcTKKvfyQtH+fsTEafWRRZ99X/xgi4ON2OsRZ738uQHw7pQT2e1v7AtN46mxO/BmhEuZQr6m6HEvxK0pJRNkBhFUiQ+poeu8j3JzicOjvPDwFE4Rjqf3RVILt83XZrju2VpRIJqAEtf//znhH8BhT5BWvhnRo+J3ML5qoZLa2joE/QK8Ctf3UPvAFkHIUMdOH2mLNgZ+U87tdVE6fYfzvphZsLxmJRG45H8ZTZuYhJbOfei2LQ4fqHmr7p8KpJNVqoz/ev1dnBclAf5ayb40qJKEVsGXIbWEbIZwg7TTsLFc29aP7DPg=" }'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate SpellCheckHandler detection
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"}
        respond_args = {"status": 500}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate SpellCheckHandler false positive detection
        expect_args = {"method": "GET", "uri": "/AAAAAAAAAAAAAA.axd"}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate ChartImage.axd Detection
        expect_args = {
            "method": "GET",
            "uri": "/ChartImage.axd",
            "query_string": "ImageName=bqYXJAqm315eEd6b%2bY4%2bGqZpe7a1kY0e89gfXli%2bjFw%3d",
        }
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/ChartImage.axd", "query_string": "ImageName="}
        respond_args = {"status": 500}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate Dialog Parameters in URL
        expect_args = {"method": "GET", "uri": "/telerik.aspx"}
        respond_args = {"response_data": '{"ImageManager":{"SerializedParameters":"MBwZB"}'}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback
        expect_args = {"uri": re.compile(r"^/\w{10}$")}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.scan.modules["telerik"].telerikVersions = ["2014.2.724", "2014.3.1024", "2015.1.204"]
        module_test.scan.modules["telerik"].DialogHandlerUrls = [
            "Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx",
            "App_Master/Telerik.Web.UI.DialogHandler.aspx",
            "AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        telerik_axd_detection = False
        telerik_axd_vulnerable = False
        telerik_spellcheck_detection = False
        telerik_dialoghandler_detection = False
        telerik_chartimage_detection = False
        telerik_http_response_parameters_detection = False

        for e in events:
            if e.type == "FINDING" and "Telerik RAU AXD Handler detected" in e.data["description"]:
                e.data["description"]
                telerik_axd_detection = True
                continue

            if e.type == "VULNERABILITY" and "Confirmed Vulnerable Telerik (version: 2014.3.1024)":
                telerik_axd_vulnerable = True
                continue

            if e.type == "FINDING" and "Telerik DialogHandler detected" in e.data["description"]:
                telerik_dialoghandler_detection = True
                continue

            if e.type == "FINDING" and "Telerik SpellCheckHandler detected" in e.data["description"]:
                telerik_spellcheck_detection = True
                continue

            if e.type == "FINDING" and "Telerik ChartImage AXD Handler Detected" in e.data["description"]:
                telerik_chartimage_detection = True
                continue

            if (
                e.type == "FINDING"
                and "Telerik DialogHandler [SerializedParameters] Detected in HTTP Response" in e.data["description"]
            ):
                telerik_http_response_parameters_detection = True
                continue

        assert telerik_axd_detection, "Telerik AXD detection failed"
        assert telerik_axd_vulnerable, "Telerik vulnerable AXD detection failed"
        assert telerik_spellcheck_detection, "Telerik spellcheck detection failed"
        assert telerik_dialoghandler_detection, "Telerik dialoghandler detection failed"
        assert telerik_chartimage_detection, "Telerik chartimage detection failed"
        assert telerik_http_response_parameters_detection, "Telerik SerializedParameters detection failed"


class TestTelerikDialogHandler_includesubdirs(TestTelerik):
    targets = ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/temp/"]
    config_overrides = {
        "modules": {
            "telerik": {
                "include_subdirs": True,
            },
        }
    }
    modules_overrides = ["httpx", "telerik"]

    async def setup_before_prep(self, module_test):
        # Simulate NO SpellCheckHandler detection (not testing for that with this test)
        expect_args = {"method": "GET", "uri": "/Telerik.Web.UI.SpellCheckHandler.axd"}
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection
        expect_args = {"method": "GET", "uri": "/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate DialogHandler detection (in /temp)
        expect_args = {"method": "GET", "uri": "/temp/App_Master/Telerik.Web.UI.DialogHandler.aspx"}
        respond_args = {
            "response_data": '<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style=\'color:red\'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div></form></body></html>'
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate /temp directory detection
        expect_args = {"method": "GET", "uri": "/temp/"}
        respond_args = {"response_data": "Temporary directory found"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["telerik"].telerikVersions = ["2014.2.724", "2014.3.1024", "2015.1.204"]
        module_test.scan.modules["telerik"].DialogHandlerUrls = [
            "App_Master/Telerik.Web.UI.DialogHandler.aspx",
        ]

    def check(self, module_test, events):
        # Check if the expected requests were made
        finding_count = sum(
            1 for e in events if e.type == "FINDING" and "Telerik DialogHandler detected" in e.data["description"]
        )
        assert finding_count == 2, "Expected 2 FINDING events (root and /temp), got {finding_count}"
