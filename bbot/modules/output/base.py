import logging
from pathlib import Path
from bbot.modules.base import BaseModule


class BaseOutputModule(BaseModule):
    accept_dupes = True
    _type = "output"
    emit_graph_trail = True
    scope_distance_modifier = None
    _stats_exclude = True

    def _event_precheck(self, event):
        if event._omit:
            return False, "_omit is True"
        if event._force_output:
            return True, "_force_output is True"
        if event._internal:
            return False, "_internal is True"
        return super()._event_precheck(event)

    def _prep_output_dir(self, filename):
        self.output_file = self.config.get("output_file", "")
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / str(filename)
        self.helpers.mkdir(self.output_file.parent)
        self._file = None

    @property
    def file(self):
        if self._file is None:
            self._file = open(self.output_file, mode="a")
        return self._file

    @property
    def config(self):
        config = self.scan.config.get("output_modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.output.{self.name}")
        return self._log
