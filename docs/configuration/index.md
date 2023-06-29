# Configuration Overview

BBOT and its modules are built to be configurable for a wide range of use cases. Config options are different from standard command-line arguments. They're designed to perform more granular changes such as setting the HTTP proxy, the global user-agent, or a module's API key.

## Configuration Files

BBOT loads its config from the following files, in this order:

- `~/.config/bbot/bbot.yml`     <-- Use this one as your main config
- `~/.config/bbot/secrets.yml`  <-- Use this one for sensitive stuff like API keys
- command line (`--config`)     <-- Use this to specify a custom config file or override individual config options

These config files will be automatically created for you when you first run BBOT.

## Command Line

Config options specified via the command-line take precedence over all others. You can give BBOT a custom config file with `--config myconf.yml`, or individual arguments like this: `--config http_proxy=http://127.0.0.1:8080 modules.shodan_dns.api_key=1234`. To display the full and current BBOT config, including any command-line arguments, use `bbot --current-config`.

Note that placing the following in `bbot.yml`:
```yaml
modules:
  shodan:
    api_key: deadbeef
```
Is the same as:
```bash
bbot --config modules.shodan.api_key=deadbeef
```

Here is an example of what a standard BBOT config might look like:
```yaml
modules:
  
```

For a list of global config options, see [Global Options](./global_options/). For a full list of module config options, see [Module Options](./module_options/)
