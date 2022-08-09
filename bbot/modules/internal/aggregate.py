from bbot.modules.base import BaseModule


class aggregate(BaseModule):
    watched_events = ["SUMMARY"]
    produced_events = ["SUMMARY"]
    flags = ["passive", "safe"]
    meta = {"description": "Report on scan statistics"}

    def report(self):
        for table_row in str(self.scan.stats).splitlines():
            self.info(table_row)
