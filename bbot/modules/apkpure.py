from pathlib import Path
from bbot.modules.base import BaseModule


class apkpure(BaseModule):
    watched_events = ["MOBILE_APP"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Download android applications from apkpure.com",
        "created_date": "2024-10-11",
        "author": "@domwhewell-sage",
    }
    options = {"output_folder": ""}
    options_desc = {"output_folder": "Folder to download apk's to"}

    async def setup(self):
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "apk_files"
        else:
            self.output_dir = self.scan.home / "apk_files"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "MOBILE_APP":
            if "android" not in event.tags:
                return False, "event is not an android app"
        return True

    async def handle_event(self, event):
        app_id = event.data.get("id", "")
        path = await self.download_apk(app_id)
        if path:
            await self.emit_event(
                {"path": str(path)},
                "FILESYSTEM",
                tags=["apk", "file"],
                parent=event,
                context=f'{{module}} downloaded the apk "{app_id}" to: {path}',
            )

    async def download_apk(self, app_id):
        path = None
        url = f"https://d.apkpure.com/b/XAPK/{app_id}?version=latest"
        self.helpers.mkdir(self.output_dir / app_id)
        file_destination = self.output_dir / app_id / f"{app_id}.xapk"
        result = await self.helpers.download(url, warn=False, filename=file_destination)
        if result:
            self.info(f'Downloaded "{app_id}" from "{url}", saved to {file_destination}')
            path = file_destination
        return path
