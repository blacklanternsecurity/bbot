# Troubleshooting

## Installation troubleshooting
- `Fatal error from pip prevented installation.`
- `ERROR: No matching distribution found for bbot`
- `bash: /home/user/.local/bin/bbot: /home/user/.local/pipx/venvs/bbot/bin/python: bad interpreter`

If you get errors resembling any of the above, you need to do something like this:
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

## Regenerate Config
As a troubleshooting step it is sometimes useful to clear out your older configs and let BBOT generate new ones. This will ensure that new defaults are property restored, etc.
```bash
# make a backup of the old configs
mv ~/.config/bbot ~/.config/bbot.bak

# generate new configs
bbot
```
