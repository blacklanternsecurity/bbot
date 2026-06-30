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
```bash
# make a backup of the old configs
mv ~/.config/bbot ~/.config/bbot.bak

# generate new configs
bbot
```
