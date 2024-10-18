from pathlib import Path
from .base import ModuleTestBase, tempapkfile


class TestAPKPure(ModuleTestBase):
    modules_overrides = ["apkpure", "google_playstore", "speculate"]
    apk_file = tempapkfile()

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.99"]}})
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/search?q=blacklanternsecurity&c=apps",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>"blacklanternsecurity" - Android Apps on Google Play</title>
            </head>
            <body>
            <a href="/store/apps/details?id=com.bbot.test&pcampaignid=dontmatchme&pli=1"/>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.bbot.test",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>BBOT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="https://www.blacklanternsecurity.com">
            </div>
            </div>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://d.apkpure.com/b/XAPK/com.bbot.test?version=latest",
            content=self.apk_file,
        )

    def check(self, module_test, events):
        assert len(events) == 6
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
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.bbot.test"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.bbot.test"
            ]
        ), "Failed to find bbot android app"
        filesystem_event = [
            e for e in events if e.type == "FILESYSTEM" and "com.bbot.test.xapk" in e.data["path"] and "apk" in e.tags
        ]
        assert 1 == len(filesystem_event), "Failed to download apk"
        file = Path(filesystem_event[0].data["path"])
        assert file.is_file(), "Destination xapk doesn't exist"
