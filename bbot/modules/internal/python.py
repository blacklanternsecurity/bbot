from bbot.modules.output.base import BaseOutputModule


class python(BaseOutputModule):
    """
    Internal module backing ``Scanner.async_start()``. The scan loop
    drains its incoming queue directly via ``_events_waiting`` and yields
    events to the API caller -- there is no real worker.

    Because the worker is a no-op, we override ``_increment_consumer_count``
    so the standard ``_module_consumers`` increment is skipped. Without this,
    every event leaks +1 on its consumer count (worker would normally
    pair the increment with a ``_minimize()`` call in its ``finally``
    block, but there is no worker here). The leak prevents
    ``_minimize()``'s ``<= 0`` block from ever firing -- bodies stay in
    memory / spill files stay on disk for the entire scan.
    """

    _type = "internal"
    watched_events = ["*"]
    meta = {"description": "Output via Python API", "created_date": "2022-09-13", "author": "@TheTechromancer"}

    async def _worker(self):
        pass

    def _increment_consumer_count(self, event):
        pass
