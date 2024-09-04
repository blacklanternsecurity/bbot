import time
import logging
from collections import deque

log = logging.getLogger("bbot.scanner.stats")


def _increment(d, k):
    try:
        d[k] += 1
    except KeyError:
        d[k] = 1


class SpeedCounter:
    """
    A simple class for keeping a rolling tally of the number of events inside a specific time window
    """

    def __init__(self, window=60):
        self.timestamps = deque()
        self.window = window

    def tick(self):
        current_time = time.time()
        self.timestamps.append(current_time)
        self.remove_old_timestamps(current_time)

    def remove_old_timestamps(self, current_time):
        while self.timestamps and current_time - self.timestamps[0] > self.window:
            self.timestamps.popleft()

    @property
    def speed(self):
        self.remove_old_timestamps(time.time())
        return len(self.timestamps)


class ScanStats:
    def __init__(self, scan):
        self.scan = scan
        self.module_stats = {}
        self.events_emitted_by_type = {}
        self.speedometer = SpeedCounter(scan.status_frequency)

    def event_produced(self, event):
        _increment(self.events_emitted_by_type, event.type)
        module_stat = self.get(event.module)
        if module_stat is not None:
            module_stat.increment_produced(event)

    def event_consumed(self, event, module):
        self.speedometer.tick()
        # skip ingress/egress modules, etc.
        if module.name.startswith("_"):
            return
        module_stat = self.get(module)
        if module_stat is not None:
            module_stat.increment_consumed(event)

    def get(self, module):
        try:
            module_stat = self.module_stats[module.name]
        except KeyError:
            module_stat = ModuleStat(module)
            self.module_stats[module.name] = module_stat
        except AttributeError:
            module_stat = None
        return module_stat

    def table(self):
        header = ["Module", "Produced", "Consumed"]
        table = []
        for mname, mstat in self.module_stats.items():
            if mname == "TARGET" or mstat.module._stats_exclude:
                continue
            table_row = []
            table_row.append(mname)
            produced_str = f"{mstat.produced_total:,}"
            produced = sorted(mstat.produced.items(), key=lambda x: x[0])
            if produced:
                produced_str += " (" + ", ".join(f"{c:,} {t}" for t, c in produced) + ")"
            table_row.append(produced_str)
            consumed_str = f"{mstat.consumed_total:,}"
            consumed = sorted(mstat.consumed.items(), key=lambda x: x[0])
            if consumed:
                consumed_str += " (" + ", ".join(f"{c:,} {t}" for t, c in consumed) + ")"
            table_row.append(consumed_str)
            table.append(table_row)
        table.sort(key=lambda x: self.module_stats[x[0]].produced_total, reverse=True)
        return [header] + table

    def _make_table(self):
        table = self.table()
        if len(table) == 1:
            table += [["None", "None", "None"]]
        return table[1:], table[0]


class ModuleStat:
    def __init__(self, module):
        self.module = module
        self.produced = {}
        self.produced_total = 0
        self.consumed = {}
        self.consumed_total = 0

    def increment_produced(self, event):
        self.produced_total += 1
        _increment(self.produced, event.type)

    def increment_consumed(self, event):
        if event.type not in ("FINISHED",):
            self.consumed_total += 1
            _increment(self.consumed, event.type)
