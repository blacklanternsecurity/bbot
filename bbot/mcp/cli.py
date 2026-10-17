"""
Renders a composed preset dict as a `bbot` command line.

This is lossless because `CapabilityPresetSchema` forbids the preset keys that
have no CLI equivalent (`conditions`, `scan_name`, `output_dir`, `module_dirs`,
verbosity). Conditions still reach a real scan, but only through `include:`d
bundled presets, which `-p` reproduces faithfully.
"""

import shlex

import yaml

# Preset key -> CLI flag, in the order they should appear on the command line.
FLAG_MAP = (
    ("include", "-p"),
    ("modules", "-m"),
    ("flags", "-f"),
    ("require_flags", "-rf"),
    ("exclude_modules", "-em"),
    ("exclude_flags", "-ef"),
    ("output_modules", "-om"),
    ("exclude_output_modules", "-eom"),
)


def flatten_config(config, prefix=""):
    """Flatten a nested config into `("a.b.c", value)` pairs."""
    pairs = []
    for key, value in config.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            pairs.extend(flatten_config(value, prefix=f"{path}."))
        else:
            pairs.append((path, value))
    return pairs


def render_config_value(value):
    """Serialize a config value so `parse_dotted_cli` reads it back unchanged."""
    if isinstance(value, str):
        return value
    rendered = yaml.safe_dump(value, default_flow_style=True, sort_keys=False).strip()
    # safe_dump terminates documents with "..." for bare scalars
    return rendered.removesuffix("...").strip()


def preset_to_cli(composed, targets, blacklist=None, scan_name=None):
    """Render the full `bbot` invocation for a composed preset plus targets."""
    argv = ["bbot", "-t", *targets]
    if blacklist:
        argv += ["-b", *blacklist]
    for key, flag in FLAG_MAP:
        values = composed.get(key)
        if values:
            argv += [flag, *values]
    for path, value in flatten_config(composed.get("config") or {}):
        argv += ["-c", f"{path}={render_config_value(value)}"]
    if scan_name:
        argv += ["-n", scan_name]
    return shlex.join(argv)


def preset_to_yaml(composed, targets=None, blacklist=None, scan_name=None):
    """Render the composed preset as a YAML file body.

    Built from the composed dict rather than `Preset.to_yaml()`, which would
    serialize the operator's merged `secrets.yml`.
    """
    document = {}
    if targets:
        document["targets"] = list(targets)
    if blacklist:
        document["blacklist"] = list(blacklist)
    if scan_name:
        document["scan_name"] = scan_name
    document.update(composed)
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False).strip()
