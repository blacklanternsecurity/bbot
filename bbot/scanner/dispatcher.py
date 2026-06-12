import logging
import traceback
import contextlib


class Dispatcher:
    """
    Enables custom hooks/callbacks on certain scan events
    """

    def set_scan(self, scan):
        self.scan = scan
        self.log = logging.getLogger("bbot.scanner.dispatcher")

    async def on_start(self, scan):
        return

    async def on_finish(self, scan):
        return

    async def on_status(self, status, scan_id):
        """
        Execute an event when the scan's status is updated
        """
        self.scan.debug(f"Setting scan status to {status}")

    @contextlib.contextmanager
    def catch(self):
        try:
            yield
        except Exception as e:
            self.log.error(f"Error in dispatcher: {e}")
            self.log.trace(traceback.format_exc())
