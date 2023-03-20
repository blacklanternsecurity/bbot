class Dispatcher:
    """
    Enables custom hooks/callbacks on certain scan events
    """

    def set_scan(self, scan):
        self.scan = scan

    def on_start(self, scan):
        return

    def on_finish(self, scan):
        return

    def on_status(self, status, scan_id):
        """
        Execute an event when the scan's status is updated
        """
        self.scan.debug(f"Setting scan status to {status}")
