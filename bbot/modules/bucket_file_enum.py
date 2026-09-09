from bbot.modules.base import BaseModule
import xml.etree.ElementTree as ET
from bbot.core.config.models import BaseModuleConfig, Field


class bucket_file_enum(BaseModule):
    """
    Enumerate files in public storage buckets

    Currently only supports AWS and DigitalOcean
    """

    watched_events = ["STORAGE_BUCKET"]
    produced_events = ["URL_UNVERIFIED"]
    meta = {
        "description": "Works in conjunction with the filedownload module to download files from open storage buckets. Currently supported cloud providers: AWS, DigitalOcean",
        "created_date": "2023-11-14",
        "author": "@TheTechromancer",
    }
    flags = ["safe", "passive", "cloud-enum"]

    class Config(BaseModuleConfig):
        file_limit: int = Field(50, description="Limit the number of files downloaded per bucket")

    scope_distance_modifier = 2

    async def setup(self):
        self.file_limit = self.config.get("file_limit", 50)
        return True

    async def handle_event(self, event):
        if "amazon" in event.tags or "digitalocean" in event.tags:
            await self.handle_aws(event)

    async def handle_aws(self, event):
        url = event.url
        urls_emitted = 0
        response = await self.helpers.request(url)
        status_code = getattr(response, "status_code", 0)
        if status_code == 200:
            content = response.text
            root = ET.fromstring(content)
            namespace = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            keys = [key.text for key in root.findall(".//s3:Key", namespace)]
            for key in keys:
                bucket_file = url + "/" + key
                file_extension = self.helpers.get_file_extension(key)
                if file_extension not in self.scan.url_extension_blacklist:
                    extension_upper = file_extension.upper()
                    await self.emit_event(
                        bucket_file,
                        "URL_UNVERIFIED",
                        parent=event,
                        tags="filedownload",
                        context=f"{{module}} enumerate files in bucket and discovered {extension_upper} file at {{event.type}}: {{event.pretty_string}}",
                    )
                    urls_emitted += 1
                    if urls_emitted >= self.file_limit:
                        return
