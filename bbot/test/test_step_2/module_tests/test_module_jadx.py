from pathlib import Path
from bbot.core.helpers.libmagic import get_magic_info
from bbot.test.test_step_2.module_tests.base import ModuleTestBase, tempapkfile

from ...bbot_fixtures import *


class TestJadx(ModuleTestBase):
    modules_overrides = ["apkpure", "google_playstore", "speculate", "jadx"]
    config_overrides = {
        "modules": {
            "apkpure": {
                "output_folder": bbot_test_dir / "apkpure",
            },
        }
    }
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
            headers={
                "Content-Type": "application/vnd.android.package-archive",
                "Content-Disposition": "attachment; filename=com.bbot.test.apk",
            },
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        apk_event = [e for e in filesystem_events if "file" in e.tags]
        extension, mime_type, description, confidence = get_magic_info(apk_event[0].data["path"])
        assert description == "Android Application Package", f"Downloaded file was detected as {description}"
        extract_event = [e for e in filesystem_events if "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract apk"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination apk doesn't exist"
