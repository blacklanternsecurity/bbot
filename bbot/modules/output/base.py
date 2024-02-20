import logging
from pathlib import Path
from bbot.modules.base import BaseModule


class BaseOutputModule(BaseModule):
    accept_dupes = True
    _type = "output"
    scope_distance_modifier = None
    _stats_exclude = True

    def _event_precheck(self, event):
        # special signal event types
        if event.type in ("FINISHED",):
            return True, "its type is FINISHED"
        if self.errored:
            return False, f"module is in error state"
        # exclude non-watched types
        if not any(t in self.get_watched_events() for t in ("*", event.type)):
            return False, "its type is not in watched_events"
        if self.target_only:
            if "target" not in event.tags:
                return False, "it did not meet target_only filter criteria"
        # exclude certain URLs (e.g. javascript):
        if event.type.startswith("URL") and self.name != "httpx" and "httpx-only" in event.tags:
            return False, "its extension was listed in url_extension_httpx_only"

        # output module specific stuff
        # omitted events such as HTTP_RESPONSE etc.
        if event._omit and not event.type in self.get_watched_events():
            return False, "_omit is True"

        # force-output certain events to the graph
        if self._is_graph_important(event):
            return True, "event is critical to the graph"

        # internal events like those from speculate, ipneighbor
        # or events that are over our report distance
        if event._internal:
            return False, "_internal is True"

        return True, "precheck succeeded"

    async def _event_postcheck(self, event):
        acceptable, reason = await super()._event_postcheck(event)
        if acceptable and not event._stats_recorded and event.type not in ("FINISHED",):
            event._stats_recorded = True
            self.scan.stats.event_distributed(event)
            self.scan.stats.event_produced(event)
        return acceptable, reason

    def is_incoming_duplicate(self, event, add=False):
        is_incoming_duplicate, reason = super().is_incoming_duplicate(event, add=add)
        # make exception for graph-important events
        if self._is_graph_important(event):
            return False, "event is graph-important"
        return is_incoming_duplicate, reason

    def _prep_output_dir(self, filename):
        self.output_file = self.config.get("output_file", "")
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / str(filename)
        self.helpers.mkdir(self.output_file.parent)
        self._file = None

    def _scope_distance_check(self, event):
        return True, ""

    @property
    def file(self):
        if getattr(self, "_file", None) is None:
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
