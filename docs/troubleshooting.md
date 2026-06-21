# Troubleshooting

## Installation troubleshooting
- `Fatal error from pip prevented installation.`
- `ERROR: No matching distribution found for bbot`
- `bash: /home/user/.local/bin/bbot: /home/user/.local/pipx/venvs/bbot/bin/python: bad interpreter`

If you get errors resembling any of the above, it's probably because your Python version is too old. To install a newer version (3.9+ is required), you will need to do something like this:
```bash
# install a newer version of python
sudo apt install python3.9 python3.9-venv
# install pipx
python3.9 -m pip install --user pipx
# add pipx to your path
python3.9 -m pipx ensurepath
# reboot
reboot
# install bbot
python3.9 -m pipx install bbot
# run bbot
bbot --help
```

## `ModuleNotFoundError`
If you run into a `ModuleNotFoundError`, try running your `bbot` command again with `--force-deps`. This will repair your modules' Python dependencies.

## Missing module commands or API key warnings
Some BBOT modules need an external command-line tool, an API key, or both. If a scan warns that a module is not installed, cannot import a dependency, or is missing an API key, use this quick checklist before filing an issue:

```bash
# show the BBOT version and confirm the active executable
bbot --version
which bbot

# reinstall module dependencies that BBOT manages
bbot --force-deps --help

# inspect the module's documented options and requirements
bbot -ml <module_name>
bbot -m <module_name> --help
```

If the module requires an API key, put it under the module's name in your BBOT config. For example:

```yaml
modules:
  shodan_dns:
    api_key: "YOUR_API_KEY_HERE"
```

The default user config is usually `~/.config/bbot/bbot.yml`. You can also keep secrets outside that file and pass them for a single run:

```bash
bbot -t example.com -m shodan_dns -c modules.shodan_dns.api_key=$SHODAN_API_KEY
```

After changing config, run a small scan with only the affected module so the error is easier to read:

```bash
bbot -t example.com -m <module_name> --force-deps -v
```

For third-party command-line tools that BBOT does not install automatically, verify they are on your `PATH` from the same shell that runs BBOT:

```bash
command -v <tool_name>
<tool_name> --version
```

If the command works in your terminal but BBOT still cannot find it, check that your shell startup files and service environment export the same `PATH`.

## Regenerate Config
As a troubleshooting step it is sometimes useful to clear out your older configs and let BBOT generate new ones. This will ensure that new defaults are property restored, etc.
```bash
# make a backup of the old configs
mv ~/.config/bbot ~/.config/bbot.bak

# generate new configs
bbot
```
