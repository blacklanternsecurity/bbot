import logging

from bbot.errors import *

log = logging.getLogger("bbot.preset.conditions")

JINJA_ENV = None


class ConditionEvaluator:
    def __init__(self, preset):
        self.preset = preset

    @property
    def context(self):
        return {
            "preset": self.preset,
            "config": self.preset.config,
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
        from jinja2.sandbox import SandboxedEnvironment

        global JINJA_ENV
        if JINJA_ENV is None:
            JINJA_ENV = SandboxedEnvironment()
        return JINJA_ENV

    def check_condition(self, condition_str, context):
        log.debug(f'Evaluating condition "{repr(condition_str)}"')
        template = self.jinja_env.from_string(condition_str)
        template.render(context)
