from bbot.modules.report.base import BaseReportModule


class aggregate(BaseReportModule):
    flags = ["passive", "safe"]
    meta = {"description": "Summarize statistics at the end of a scan"}

    async def report(self):
        self.log_table(*self.scan.stats._make_table(), table_name="scan-stats")
