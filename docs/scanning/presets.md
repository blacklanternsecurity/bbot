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

BBOT has a ready-made collection of presets for common tasks like subdomain enumeration and web spidering. They live in `~/.bbot/presets`.

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
  - web-basic

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

## Validating Presets

To make sure BBOT is configured the way you expect, you can always check the `--current-preset` to show the final version of the config that will be used when BBOT executes:

```bash
# verify the preset is what you want
bbot -p ./mypreset.yml --current-preset
```

## Advanced Usage

BBOT Presets support advanced features like environment variable substitution and custom conditions.

### Custom Modules

If you want to use a custom BBOT `.py` module, you can either move it into `bbot/modules` where BBOT is installed, or add its parent folder to `module_dirs` like so:

```yaml title="custom_modules.yml"
# load extra BBOT modules from this locaation
module_dirs:
  - /home/user/custom_modules
```

### Environment Variables

You can insert environment variables into your preset like this: `${env:<variable>}`:

```yaml title="my_nuclei.yml"
description: Do a nuclei scan

target:
  - evilcorp.com

modules:
  - nuclei

config:
  modules:
    nuclei:
      # allow the nuclei templates to be specified at runtime via an environment variable
      tags: ${env:NUCLEI_TAGS}
```

```bash
NUCLEI_TAGS=apache,nginx bbot -p ./my_nuclei.yml
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
description: Enable ffuf but only when the web spider isn't also enabled

modules:
  - ffuf

conditions:
  - |
    {% if config.web.spider_distance > 0 and config.web.spider_depth > 0 %}
      {{ warn("Disabling ffuf because the web spider is enabled") }}
      {{ preset.exclude_module("ffuf") }}
    {% endif %}
```

Conditions use [Jinja](https://palletsprojects.com/p/jinja/), which means they can contain Python code. They run inside a sandboxed environment which has access to the following variables:

- `preset` - the current preset object
- `config` - the current config (an alias for `preset.config`)
- `warn(message)` - display a custom warning message to the user
- `abort(message)` - abort the scan with an optional message

If you aren't able to accomplish what you want with conditions, or if you need access to a new variable/function, please let us know on [Github](https://github.com/blacklanternsecurity/bbot/issues/new/choose).
