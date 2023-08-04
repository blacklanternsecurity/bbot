import logging
import traceback

log = logging.getLogger("bbot.scanner.dispatcher")


class Dispatcher:
    """
    Enables custom hooks/callbacks on certain scan events
    """

    def set_scan(self, scan):
        self.scan = scan

    async def on_start(self, scan):
        return

    async def on_finish(self, scan):
        return

    async def on_status(self, status, scan_id):
        """
        Execute an event when the scan's status is updated
        """
        self.scan.debug(f"Setting scan status to {status}")

    async def catch(self, callback, *args, **kwargs):
        try:
            return await callback(*args, **kwargs)
        except Exception as e:
            log.error(f"Error in {callback.__qualname__}(): {e}")
            log.trace(traceback.format_exc())
