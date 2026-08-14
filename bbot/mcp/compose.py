"""
Prepares one capability preset for a scan.

There is nothing to compose. A BBOT scan is a module set fed into a recursive
engine, and a capability is one such set, so running two capabilities is not a
pipeline to be wired up -- it is just a longer module list. What is left here is
the part that genuinely needs care: keeping model-supplied targets away from
BBOT's file-reading target parser, and surfacing the warnings a preset's own
jinja conditions raise.
"""

from bbot.errors import ValidationError

# Longer than the longest legal FQDN or any realistic URL. Anything past this is
# not a target, and letting it reach the filesystem lookup raises OSError.
MAX_TARGET_LENGTH = 2048
# What DNS allows a name and one of its dot-separated pieces to be.
MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63


class ComposeError(Exception):
    """A request that cannot produce a usable scan."""


def _check_host_shape(entry):
    """Reject a bare token too long to be a hostname.

    `BBOTTarget` is the check for whether a target is a host at all, but it reads
    an unadorned word as a DNS name, and a word has no length it stops being one
    at. DNS does: 253 characters for a name and 63 for a label. A URL may be
    longer than either, so only unadorned targets are held to them.
    """
    if "://" in entry or "@" in entry:
        return
    host = entry.split("/", 1)[0]
    if len(host) > MAX_HOSTNAME_LENGTH:
        raise ComposeError(
            f"Target is {len(host)} characters, and a hostname stops at {MAX_HOSTNAME_LENGTH}: {entry[:60]!r}..."
        )
    for label in host.split("."):
        if len(label) > MAX_LABEL_LENGTH:
            raise ComposeError(
                f"Target has a {len(label)}-character piece between dots, and a hostname's stops at "
                f"{MAX_LABEL_LENGTH}: {entry[:60]!r}..."
            )


def validate_targets(targets, blacklist=None):
    """
    Check targets without letting them near `Preset.from_dict()`.

    `Preset.from_dict` runs targets through `_resolve_file_entries` and
    `chain_lists(try_files=True)`, which reads any entry that resolves to a file
    and splits it into individual targets. Since a scan echoes its targets back
    to the caller, routing model-supplied strings through that path would turn
    this into an arbitrary file read. `BBOTTarget` does no file resolution and
    rejects anything that isn't a host, IP, network, URL, or email.
    """
    from bbot.scanner.preset.path import PRESET_PATH
    from bbot.scanner.target import BBOTTarget

    targets = list(targets or [])
    blacklist = list(blacklist or [])
    if not targets:
        raise ComposeError("At least one target is required.")

    for entry in targets + blacklist:
        if not isinstance(entry, str):
            raise ComposeError(f"Targets must be strings, got {type(entry).__name__}.")
        if not entry.strip():
            raise ComposeError("Empty target.")
        if len(entry) > MAX_TARGET_LENGTH:
            raise ComposeError(f"Target is {len(entry)} characters, which is longer than any real host or URL.")
        try:
            resolves_to_file = PRESET_PATH.find_file(entry) is not None
        except (OSError, ValueError):
            # a hostile string can make the filesystem lookup itself raise
            # (null bytes, oversized path components); not a valid target either way
            raise ComposeError(f"Invalid target: {entry!r}")
        if resolves_to_file:
            raise ComposeError(
                f'Refusing to treat "{entry}" as a target because it resolves to a file on disk. '
                f"Pass targets literally (hostnames, IPs, CIDRs, URLs)."
            )
        _check_host_shape(entry)

    try:
        BBOTTarget(target=targets, blacklist=blacklist)
    except ValidationError as e:
        raise ComposeError(f"Invalid target: {e}")

    return targets, blacklist


class CollectingConditionEvaluator:
    """
    Runs a preset's jinja conditions without a scan, collecting their messages
    instead of logging or raising.

    Conditions are how bundled presets warn about bad combinations. Since a
    capability can `include:` any of them, those warnings have to reach the agent
    rather than a log file nobody reads. `ConditionEvaluator` only touches
    `preset.config`, `preset.force_start` and `preset.conditions`, so it runs
    fine outside a scan.
    """

    def __init__(self, preset):
        from bbot.scanner.preset.conditions import ConditionEvaluator

        self.warnings = []
        self.aborts = []
        evaluator = ConditionEvaluator(preset)
        evaluator.warn = self.warnings.append
        evaluator.abort = self.aborts.append
        self._evaluator = evaluator

    def evaluate(self):
        try:
            self._evaluator.evaluate()
        except Exception as e:
            self.warnings.append(f"Could not evaluate preset conditions: {e}")
        return self


def prepare(entry, targets, blacklist=None):
    """
    Validate a request against one capability. Returns `(targets, blacklist, warnings)`.

    Raises `ComposeError` when the request could not run.
    """
    targets, blacklist = validate_targets(targets, blacklist)

    try:
        facts = entry.facts
    except ValidationError as e:
        raise ComposeError(f"BBOT rejected this preset: {e}")
    if not facts.modules:
        raise ComposeError(
            f'"{entry.name}" enables zero scan modules, so the scan would find nothing. Its preset needs fixing.'
        )

    from bbot.mcp.derive import bake_preset_dict

    _, baked = bake_preset_dict(entry.capability.preset.to_preset_dict(), name=entry.name)
    conditions = CollectingConditionEvaluator(baked).evaluate()
    warnings = list(conditions.warnings)
    warnings.extend(f"A preset requested abort: {a}" for a in conditions.aborts)

    return targets, blacklist, warnings
