# Presets

Once you start customizing BBOT, your commands can start to get really long. Presets let you put all your scan settings in a single file:

```bash
bbot -p ./my_preset.yml
```

A Preset is a YAML file that can include scan targets, modules, and config options like API keys.

A typical preset looks like this:

<!-- BBOT SUBDOMAIN ENUM PRESET -->
```yaml title="subdomain-enum.yml"
description: Enumerate subdomains via APIs, brute-force

flags:
  - subdomain-enum

output_modules:
  - subdomains

```
<!-- END BBOT SUBDOMAIN ENUM PRESET -->

## How to use Presets (`-p`)

BBOT ships with a collection of presets for common tasks like subdomain enumeration and web spidering. The defaults live in `bbot/presets` inside the installed package. You can also place custom presets anywhere and reference them by path.

To list them, you can do:

```bash
# list available presets
bbot -lp
```

Enable them with `-p`:

```bash
# do a subdomain enumeration
bbot -t evilcorp.com -p subdomain-enum

# multiple presets - subdomain enumeration + web spider
bbot -t evilcorp.com -p subdomain-enum spider

# start with a preset but only enable modules that have the 'passive' flag
bbot -t evilcorp.com -p subdomain-enum -rf passive

# preset + manual config override
bbot -t www.evilcorp.com -p spider -c web.spider_distance=10
```

You can build on the default presets, or create your own. Here's an example of a custom preset that builds on `subdomain-enum`:

```yaml title="my_subdomains.yml"
description: Do a subdomain enumeration + basic web scan + nuclei

target:
  - evilcorp.com

include:
  # include these default presets
  - subdomain-enum
  - web

modules:
  # enable nuclei in addition to the other modules
  - nuclei

config:
  # global config options
  web:
    http_proxy: http://127.0.0.1:8080
  # module config options
  modules:
    # api keys
    securitytrails:
      api_key: 21a270d5f59c9b05813a72bb41707266
    virustotal:
      # multiple API keys are allowed
      api_key:
        - 4f41243847da693a4f356c0486114bc6
        - 5bc6ed268ab6488270e496d3183a1a27
```

To execute your custom preset, you do:

```bash
bbot -p ./my_subdomains.yml
```

## Preset Load Order

When you enable multiple presets, the order matters. In the case of a conflict, the last preset will always win. This means, for example, if you have a custom preset called `my_spider` that sets `web.spider_distance` to 1:

```yaml title="my_spider.yml"
config:
  web:
    spider_distance: 1
```

...and you enable it alongside the default `spider` preset in this order:

```bash
bbot -t evilcorp.com -p ./my_spider.yml spider
```

...the value of `web.spider_distance` will be overridden by `spider`. To ensure this doesn't happen, you would want to switch the order of the presets:

```bash
bbot -t evilcorp.com -p spider ./my_spider.yml
```

## Preset Validation

BBOT automatically validates presets when they load. If your preset has a typo in a top-level key, an unknown module name, or an invalid config option, BBOT will catch it and suggest the closest match:

```text
$ bbot -p ./mypreset.yml
ERROR  [preset:modlues] Could not find preset option "modlues". Did you mean "modules"?
```

This also applies to module config and flags -- for example, misspelling a module name under `config.modules` or using a flag that doesn't exist will produce a helpful error.

To inspect the final merged preset that BBOT will use (after all includes and overrides are applied), use `--current-preset`:

```bash
# show the final resolved preset
bbot -p ./mypreset.yml --current-preset

# show the full config including defaults
bbot -p ./mypreset.yml --current-preset-full
```

## Preset YAML Reference

Here is the full list of supported top-level keys in a preset YAML file:

| Key | Type | Description |
|-----|------|-------------|
| `target` (or `targets`) | list | In-scope targets (see [Accepted Input Types](index.md#accepted-input-types)) |
| `seeds` | list | Seed events to feed into modules. If omitted, targets are used as seeds |
| `blacklist` | list | Excluded targets. Takes ultimate precedence |
| `modules` | list | Scan modules to enable |
| `output_modules` | list | Output modules (default: `csv`, `txt`, `json`) |
| `exclude_modules` | list | Modules to exclude |
| `flags` | list | Enable all modules with these flags |
| `require_flags` | list | Only enable modules that have these flags |
| `exclude_flags` | list | Exclude modules that have any of these flags |
| `config` | dict | Config overrides (global and per-module) |
| `include` (or `presets`) | list | Other presets to include |
| `module_dirs` | list | Additional directories to load modules from |
| `conditions` | list | Jinja2 conditions evaluated before scan start |
| `scan_name` | string | Custom scan name (default: random, e.g. `demonic_jimmy`) |
| `output_dir` | string | Custom output directory (default: `~/.bbot`) |
| `description` | string | Human-readable description of the preset |
| `verbose` | bool | Enable verbose logging |
| `debug` | bool | Enable debug logging |
| `silent` | bool | Silence all stderr output |

## Advanced Usage

BBOT Presets support advanced features like file-based targets, custom modules, and custom conditions.

### Files as Targets

You can specify file paths in your preset's `target`, `seeds`, or `blacklist` fields. BBOT will read each file and expand its lines as individual entries:

```yaml title="my_preset.yml"
target:
  - targets.txt
  - extra.evilcorp.com

seeds:
  - seeds.txt

blacklist:
  - /home/user/blacklist.txt
```

Relative paths (like `targets.txt`) are resolved relative to the preset file's directory first, then the current working directory. Absolute paths are used as-is.

You can mix file paths and literal targets in the same list. If an entry doesn't point to an existing file, it is treated as a literal target.

### Custom Modules

If you want to use a custom BBOT `.py` module, you can either move it into `bbot/modules` where BBOT is installed, or add its parent folder to `module_dirs` like so:

```yaml title="custom_modules.yml"
# load extra BBOT modules from this location
module_dirs:
  - /home/user/custom_modules
```

### Conditions

Sometimes, you might need to add custom logic to a preset. BBOT supports this via `conditions`. The `conditions` attribute allows you to specify a list of custom conditions that will be evaluated before the scan starts. This is useful for performing last-minute sanity checks, or changing the behavior of the scan based on custom criteria.

```yaml title="my_preset.yml"
description: Abort if nuclei templates aren't specified

modules:
  - nuclei

conditions:
  - |
    {% if not config.modules.nuclei.templates %}
      {{ abort("Don't forget to set your templates!") }}
    {% endif %}
```

```yaml title="my_preset.yml"
description: Enable webbrute but only when the web spider isn't also enabled

modules:
  - webbrute

conditions:
  - |
    {% if config.web.spider_distance > 0 and config.web.spider_depth > 0 %}
      {{ warn("Disabling webbrute because the web spider is enabled") }}
      {{ preset.exclude_module("webbrute") }}
    {% endif %}
```

Conditions use [Jinja](https://palletsprojects.com/p/jinja/), which means they can contain Python code. They run inside a sandboxed environment which has access to the following variables:

- `preset` - the current preset object
- `config` - the current config (an alias for `preset.config`)
- `warn(message)` - display a custom warning message to the user
- `abort(message)` - abort the scan with an optional message

If you aren't able to accomplish what you want with conditions, or if you need access to a new variable/function, please let us know on [Github](https://github.com/blacklanternsecurity/bbot/issues/new/choose).

[Next Up: Events -->](./events.md){ .md-button .md-button--primary }
