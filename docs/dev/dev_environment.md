# Setting Up a Dev Environment

The following will show you how to set up a fully functioning python environment for devving on BBOT.

## Installation (Poetry)

[Poetry](https://python-poetry.org/) is the recommended method of installation if you want to dev on BBOT. To set up a dev environment with Poetry, you can follow these steps:

- Fork [BBOT](https://github.com/blacklanternsecurity/bbot) on GitHub
- Clone your fork and set up a development environment with Poetry:

```bash
# clone your forked repo and cd into it
git clone git@github.com/<username>/bbot.git
cd bbot

# install poetry
curl -sSL https://install.python-poetry.org | python3 -

# install pip dependencies
poetry install
# install pre-commit hooks, etc.
poetry run pre-commit install

# enter virtual environment
poetry shell

bbot --help
```

- Now, any changes you make in the code will be reflected in the `bbot` command.
- After making your changes, run the tests locally to ensure they pass.

```bash
# auto-format code indentation, etc.
ruff format

# run tests
./bbot/test/run_tests.sh
```

- Finally, commit and push your changes, and create a pull request to the `dev` branch of the main BBOT repo.
