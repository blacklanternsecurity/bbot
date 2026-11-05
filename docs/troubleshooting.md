# Troubleshooting

## Installation Troubleshooting
- `Fatal error from pip prevented installation.`
- `ERROR: No matching distribution found for bbot`

If you get errors like the above, it's probably because your Python version is too old. BBOT requires Python 3.10+.

```bash
# install a newer version of python
sudo apt install python3.12 python3.12-venv
# install pipx
python3.12 -m pip install --user pipx
# add pipx to your path
python3.12 -m pipx ensurepath
# reboot
reboot
# install bbot
python3.12 -m pipx install bbot
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

# inspect the module's options and requirements, including any api_key
bbot -mh <module_name>
```

If the module requires an API key, put it in `secrets.yml` under the module's name:

```yaml title="~/.config/bbot/secrets.yml"
modules:
  shodan_dns:
    api_key: "YOUR_API_KEY_HERE"
```

You can also keep the key out of that file and pass it for a single run:

```bash
bbot -t example.com -m shodan_dns -c modules.shodan_dns.api_key=$SHODAN_API_KEY
```

After changing config, run a small scan with only the affected module so the error is easier to read. Dependencies install when a scan runs, so this is also what repairs them:

```bash
bbot -t example.com -m <module_name> --force-deps -v
```

For third-party command-line tools that BBOT does not install automatically, verify they are on your `PATH` from the same shell that runs BBOT:

```bash
command -v <tool_name>
<tool_name> --version
```

If the command works in your terminal but BBOT still cannot find it, check that your shell startup files and service environment export the same `PATH`.

## Clear BBOT Cache
BBOT caches module data, wordlists, and other resources under `~/.bbot`. After an upgrade, stale cache files can sometimes cause unexpected errors. If you're seeing strange behavior after updating, try clearing it:

```bash
# remove the BBOT cache directory
rm -rf ~/.bbot

# BBOT will recreate it on the next run
bbot --help
```

## Regenerate Config
As a troubleshooting step it is sometimes useful to clear out your older configs and let BBOT generate new ones. This will ensure that new defaults are properly restored, etc.

BBOT can do this for you (it backs up the originals first):

```bash
# regenerate config and/or secrets from current defaults
bbot --reset-config --yes
bbot --reset-secrets --yes
```

Or do it manually:

```bash
# make a backup of the old configs
mv ~/.config/bbot ~/.config/bbot.bak

# generate new configs
bbot
```
