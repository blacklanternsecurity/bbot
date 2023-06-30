from bbot.modules.output.base import BaseOutputModule


class python(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output via Python API"}

    async def _worker(self):
        pass
