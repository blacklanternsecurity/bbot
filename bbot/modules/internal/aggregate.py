from bbot.modules.base import BaseModule


class aggregate(BaseModule):
    watched_events = ["SUMMARY"]
    produced_events = ["SUMMARY"]
    flags = ["passive", "safe"]

    def report(self):
        for table_row in str(self.scan.stats).splitlines():
            self.info(table_row)
