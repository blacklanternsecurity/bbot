# Validating, Sanitizing, and Inspecting Presets

BBOT's preset and module configs are described by [pydantic](https://docs.pydantic.dev/) models — the same models that power `bbot -l` and `bbot --help`. The helpers below let you reuse those models from your own code to validate a preset, redact sensitive values, or dump module metadata.

All of these helpers work on plain dicts (i.e. what you'd get from `yaml.safe_load`), so you can call them before instantiating a `Preset` or `Scanner`.

## Validate a preset

[`validate_preset`](https://github.com/blacklanternsecurity/bbot/blob/dev/bbot/scanner/preset/validate.py) catches typos and type errors in one pass — top-level preset keys, global config, unknown module names, and per-module options:

```python
from bbot.scanner import validate_preset

errors = validate_preset({
    "modules": ["nuclei"],
    "config": {
        "scope": {"strict": True},
        "modules": {"nuclei": {"ratelimit": 200}},
    },
})

for err in errors:
    print(err)
```

Empty list → valid. Each [`PresetValidationError`](https://github.com/blacklanternsecurity/bbot/blob/dev/bbot/scanner/preset/validate.py) carries a `where` (e.g. `"preset"`, `"config"`, `"module:nuclei"`), a dotted `path`, and a human-readable `message` with closest-match suggestions when applicable. To validate a YAML file directly, use `validate_preset_file(path)`.

## Redact secrets from a config

Each module's `class Config(BaseModuleConfig)` declares which fields are sensitive (`sensitive=True`) and/or required (`mandatory=True`). `BBOTCore.no_secrets_config()` walks the config dict alongside those schemas and removes only fields explicitly marked sensitive — no fuzzy name matching:

```python
from bbot.core import CORE

config = {
    "interactsh_token": "leaky",
    "web": {"http_cookies": {"session": "abc"}},
    "modules": {
        "shodan_dns": {"api_key": "sh-secret"},
        "robots": {"include_sitemap": True},
    },
}

print(CORE.no_secrets_config(config))
# {'web': {}, 'modules': {'shodan_dns': {}, 'robots': {'include_sitemap': True}}}

print(CORE.secrets_only_config(config))
# {'interactsh_token': 'leaky', 'web': {'http_cookies': {'session': 'abc'}}, ...}
```

The `Preset.to_dict()` method exposes the same behavior via a `redact_secrets=True` flag:

```python
preset.to_dict(include_target=True, redact_secrets=True)
```

## Mark your own fields sensitive or mandatory

When you write a module, import `Field` from `bbot.core.config.models` (not from `pydantic` directly) so the `sensitive` and `mandatory` keyword args are accepted:

```python
from bbot.core.config.models import BaseModuleConfig, Field


class my_module(BaseModule):
    class Config(BaseModuleConfig):
        api_key: str = Field("", description="My API key", sensitive=True, mandatory=True)
        verbose: bool = Field(False, description="Print extra detail")
```

- `sensitive=True` — value is redacted by `no_secrets_config()` / `Preset.to_dict(redact_secrets=True)` and lives in `~/.config/bbot/secrets.yml` rather than `bbot.yml`.
- `mandatory=True` — module needs this option to function. Drives the **Needs API Key** column in `bbot -l` and the runtime `BaseModule.auth_required` property.

A field can carry both, just one, or neither.

## Dump all module metadata

`MODULE_LOADER.preloaded()` returns the full preload dict for every module — descriptions, flags, watched/produced events, deps, and (since the field-metadata refactor) the per-module `options_sensitive` and `options_mandatory` field-name sets:

```python
from bbot.core.modules import MODULE_LOADER

MODULE_LOADER.preload()
shodan = MODULE_LOADER.preloaded()["shodan_dns"]
print(shodan["options_mandatory"])  # ['api_key']
print(shodan["options_sensitive"])  # ['api_key']
```

For pretty-printed tables, use `MODULE_LOADER.modules_table()` (module summary) or `MODULE_LOADER.modules_options_table()` (per-option name/type/description/default) — these are what `bbot -l` and `bbot --help -m <module>` render.

## Filter options by `sensitive` / `mandatory`

To collect dotted-path keys (e.g. `modules.shodan_dns.api_key`) for every option carrying a particular flag, you have two options depending on scope.

**Per-module only** — fast, no schema walk. The flag sets are pre-extracted on each preloaded module, so this is just a dict comprehension:

```python
from bbot.core.modules import MODULE_LOADER

MODULE_LOADER.preload()

sensitive_paths = [
    f"modules.{name}.{opt}"
    for name, p in MODULE_LOADER.preloaded().items()
    for opt in p.get("options_sensitive") or []
]

mandatory_paths = [
    f"modules.{name}.{opt}"
    for name, p in MODULE_LOADER.preloaded().items()
    for opt in p.get("options_mandatory") or []
]

# Both flags at once (e.g. an api-key audit — fields a module needs *and* hides):
both = [
    f"modules.{name}.{opt}"
    for name, p in MODULE_LOADER.preloaded().items()
    for opt in set(p.get("options_sensitive") or []) & set(p.get("options_mandatory") or [])
]
```

**Per-module *and* global** — walk `MODULE_LOADER.config_schema`, which is the composite pydantic model with global keys (e.g. `interactsh_token`, `web.http_cookies`) and every module's `Config` grafted in under `modules.<name>`:

```python
import typing
from pydantic import BaseModel
from bbot.core.config.models import is_sensitive, is_mandatory

def schema_paths(model, *, predicate, prefix=""):
    """Yield dotted paths for every field where `predicate(FieldInfo)` is True."""
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        ann = field.annotation
        # unwrap Optional[X]
        if typing.get_origin(ann) is typing.Union:
            ann = next((a for a in typing.get_args(ann) if a is not type(None)), ann)
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            yield from schema_paths(ann, predicate=predicate, prefix=f"{path}.")
        elif predicate(field):
            yield path

all_sensitive = list(schema_paths(MODULE_LOADER.config_schema, predicate=is_sensitive))
# ['web.http_cookies', 'interactsh_token', 'modules.shodan_dns.api_key', ...]
```

The same pattern works for any field-metadata key you stash via `Field(..., json_schema_extra={...})` — swap the `predicate` for your own check.
