from bbot.modules.output.base import BaseOutputModule


class python(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output via Python API", "created_date": "2022-09-13", "author": "@TheTechromancer"}

    async def _worker(self):
        pass
