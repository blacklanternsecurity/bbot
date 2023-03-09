from bbot.modules.report.base import BaseReportModule


class aggregate(BaseReportModule):
    flags = ["passive", "safe"]
    meta = {"description": "Summarize statistics at the end of a scan"}

    def report(self):
        for table_row in str(self.scan.stats).splitlines():
            self.info(table_row)
