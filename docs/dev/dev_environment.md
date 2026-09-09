# Setting Up a Dev Environment

The following will show you how to set up a fully functioning python environment for devving on BBOT.

## Installation (uv)

[uv](https://docs.astral.sh/uv/) is the recommended method of installation if you want to dev on BBOT. To set up a dev environment with uv, you can follow these steps:

- Fork [BBOT](https://github.com/blacklanternsecurity/bbot) on GitHub
- Clone your fork and set up a development environment with uv:

```bash
# clone your forked repo and cd into it
git clone git@github.com:<username>/bbot.git
cd bbot

# switch to the dev branch and create a feature branch
git checkout dev
git checkout -b my-feature

# install uv (if you haven't already)
curl -LsSf https://astral.sh/uv/install.sh | sh

# install pip dependencies
uv sync --group dev
# install pre-commit hooks
uv run pre-commit install

# enter virtual environment
source .venv/bin/activate

bbot --help
```

- Now, any changes you make in the code will be reflected in the `bbot` command.
- After making your changes, run the tests locally to ensure they pass.

```bash
# lint and auto-format
ruff check
ruff format

# run tests
./bbot/test/run_tests.sh
```

- Finally, commit and push your changes, and create a pull request to the `dev` branch of the main BBOT repo.
