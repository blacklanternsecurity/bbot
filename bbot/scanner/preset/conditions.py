import copy
import logging
from contextlib import suppress

from bbot.errors import *

log = logging.getLogger("bbot.preset.conditions")

JINJA_ENV = None


class ConditionEvaluator:
    def __init__(self, preset):
        self.preset = preset

    def _snapshot(self):
        # conditions see a read-only, deep-copied data snapshot of the preset, never the live object:
        # a template resolves preset.<field> via item access, so reads keep working, but there are no
        # methods or nested live objects (core, module_loader, scan) to call.
        preset = self.preset
        config = copy.deepcopy(preset.config)
        snapshot = {
            "config": config,
            "modules": sorted(preset.modules),
            "scan_modules": list(preset.scan_modules),
            "output_modules": list(preset.output_modules),
            "internal_modules": list(preset.internal_modules),
            "exclude_modules": sorted(preset.exclude_modules),
            "flags": sorted(preset.flags),
            "require_flags": sorted(preset.require_flags),
            "exclude_flags": sorted(preset.exclude_flags),
            "module_dirs": sorted(str(d) for d in preset.module_dirs),
            "scan_name": preset.scan_name,
            "name": preset.name,
            "description": preset.description,
            "verbose": preset.verbose,
            "debug": preset.debug,
            "silent": preset.silent,
            "force_start": preset.force_start,
        }
        # available only once the preset is baked (which it is when conditions run); stringify to data
        for attr in ("target", "whitelist", "blacklist", "seeds"):
            with suppress(Exception):
                snapshot[attr] = str(getattr(preset, attr))
        return snapshot

    @property
    def context(self):
        snapshot = self._snapshot()
        return {
            "preset": snapshot,
            "config": snapshot["config"],
            "abort": self.abort,
            "warn": self.warn,
        }

    def abort(self, message):
        if not self.preset.force_start:
            raise PresetAbortError(message)

    def warn(self, message):
        log.warning(message)

    def evaluate(self):
        context = self.context
        already_evaluated = set()
        for preset_name, condition in self.preset.conditions:
            condition_str = str(condition)
            if condition_str not in already_evaluated:
                already_evaluated.add(condition_str)
                try:
                    self.check_condition(condition_str, context)
                except PresetAbortError as e:
                    raise PresetAbortError(f'Preset "{preset_name}" requested abort: {e} (--force to override)')

    @property
    def jinja_env(self):
        from jinja2.sandbox import ImmutableSandboxedEnvironment

        global JINJA_ENV
        if JINJA_ENV is None:
            JINJA_ENV = ImmutableSandboxedEnvironment()
        return JINJA_ENV

    def check_condition(self, condition_str, context):
        log.debug(f'Evaluating condition "{repr(condition_str)}"')
        template = self.jinja_env.from_string(condition_str)
        template.render(context)
