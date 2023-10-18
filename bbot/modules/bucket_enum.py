from bbot.modules.base import BaseModule
import xml.etree.ElementTree as ET

class bucket_enum(BaseModule):
    """
    Enumerate files in a public bucket
    """
    scope_distance_modifier = 1
    watched_events = ["STORAGE_BUCKET"]
    produced_events = ["BUCKET_FILE"]
    flags = ["passive", "safe", "cloud-enum"]

    async def handle_event(self, event):
        url = event.data["url"]
        response = await self.helpers.request(url)
        if response.status_code == 200:
            content = response.text
            root = ET.fromstring(content)
            namespace = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            keys = [key.text for key in root.findall('.//s3:Key', namespace)]
            self.hugesuccess(f"Keys: {keys}")
            for key in keys:
                bucket_file = url + "/" + key
                self.emit_event(bucket_file, "BUCKET_FILE", source=event)