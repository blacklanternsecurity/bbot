# Contributing to BBOT

First off, thank you for considering contributing to BBOT! 🎉

BBOT is a community-driven OSINT / reconnaissance framework, and every contribution — whether it's a new module, a bug fix, an improvement to the docs, or a typo correction — helps make the tool better for everyone.

This guide walks you through the process of contributing, setting up a development environment, and submitting a pull request.

---

## 📜 Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How Can I Contribute?](#how-can-i-contribute)
3. [Reporting Bugs](#reporting-bugs)
4. [Suggesting Enhancements](#suggesting-enhancements)
5. [Development Setup](#development-setup)
6. [Project Layout](#project-layout)
7. [Code Style](#code-style)
8. [Testing](#testing)
9. [Submitting a Pull Request](#submitting-a-pull-request)
10. [Writing a New Module](#writing-a-new-module)
11. [Release Process](#release-process)

---

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## How Can I Contribute?

There are many ways to contribute to BBOT:

- **🐛 Report bugs** — open an issue describing the problem and how to reproduce it.
- **💡 Suggest enhancements** — open an issue with the `enhancement` label.
- **🧩 Write a new module** — BBOT is modular; new scan modules, output modules, and helpers are always welcome (see [Writing a New Module](#writing-a-new-module)).
- **📖 Improve documentation** — typos, broken links, missing examples, and doc clarifications.
- **🧪 Add tests** — improve coverage on existing or new code paths.
- **🔧 Refactor / fix bugs** — small cleanups or larger refactors of the core scanner.

If you're new to the codebase, look for issues labeled `good first issue` on the [issue tracker](https://github.com/blacklanternsecurity/bbot/issues).

## Reporting Bugs

Before opening a bug report:

1. **Search existing issues** to see if it has already been reported.
2. **Check the version** — confirm the bug exists on the latest `dev` branch.
3. **Gather details** — BBOT version (`bbot --version`), OS, Python version, target domain (redact if sensitive), and the exact command you ran.

Then open a GitHub issue and include:

- A clear, descriptive title.
- A **minimal reproducible example** (commands + config).
- The **expected behavior** vs. the **actual behavior**.
- Relevant logs (set `-d` / `--debug` if needed and **redact API keys / targets**).
- Any non-default modules or flags you enabled.

## Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When opening one:

- Use a clear, descriptive title.
- Describe the **use case** — what are you trying to accomplish?
- Explain **why** the current behavior is insufficient.
- Sketch the **proposed solution** (API, CLI flag, config option, etc.).
- Note any **alternatives** you considered.

## Development Setup

BBOT targets **Python 3.9+** and uses [Poetry](https://python-poetry.org/) for dependency management. [Pre-commit](https://pre-commit.com/) is used to enforce code style and run sanity hooks.

### 1. Fork & Clone

```bash
# 1. Fork the repo on GitHub (click "Fork" on the project page)
# 2. Clone your fork
git clone https://github.com/<your-username>/bbot.git
cd bbot

# 3. Add the upstream remote
git remote add upstream https://github.com/blacklanternsecurity/bbot.git
```

### 2. Install Poetry (if you don't have it)

```bash
pipx install poetry
# or
curl -sSL https://install.python-poetry.org | python3 -
```

### 3. Install Dependencies

```bash
# Install bbot and all dev dependencies
poetry install

# Activate the virtual environment
poetry shell
```

Verify the install:

```bash
bbot --version
bbot --help
```

### 4. Install Pre-commit Hooks

```bash
pipx install pre-commit   # or: brew install pre-commit
pre-commit install
```

Pre-commit will now run Ruff, formatting checks, and basic file sanity checks on every commit.

### 5. (Optional) Docker Setup

If you'd rather develop inside a container, the project ships a `Dockerfile` and a helper script:

```bash
./bbot-docker.sh
```

## Project Layout

```
bbot/
├── bbot/                   # Main package
│   ├── cli.py              # CLI entry point
│   ├── scanner.py          # Core scan engine
│   ├── modules/            # Scan modules (dns brute, subdomain enum, etc.)
│   ├── helpers/            # Helpers (dnsresolve, crawl, etc.)
│   ├── output_modules/     # Output modules (neo4j, json, splunk, …)
│   └── core/               # Event framework, config, networking
├── docs/                   # MkDocs documentation source
├── examples/               # Example configs and targets
├── extra_sass/             # Distro-specific extras (Kali, Debian, …)
├── .github/workflows/      # CI pipelines (tests, distro tests, codeql, …)
├── pyproject.toml          # Poetry project + tool config
├── mkdocs.yml              # Docs site config
└── Dockerfile              # Container image
```

## Code Style

BBOT uses [Ruff](https://docs.astral.sh/ruff/) for linting and import sorting. The configuration lives in `pyproject.toml` and the pre-commit hook runs Ruff at the version pinned in `.pre-commit-config.yaml`.

Key conventions:

- **Line length:** 200 (configured in `pyproject.toml` under `[tool.ruff]`).
- **Imports:** sorted by Ruff (`I` rules).
- **Type hints:** encouraged for new public APIs.
- **Docstrings:** Google-style for new modules / functions when behavior is non-obvious.
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants.
- **Avoid breaking changes** to the public event / module API without prior discussion in an issue.

Run Ruff manually before committing:

```bash
ruff check .
ruff format .
```

## Testing

BBOT's test suite lives alongside the package. To run it:

```bash
# Run the full test suite
poetry run pytest

# Run a single test file
poetry run pytest bbot/test/test_scanner.py

# Run a single test by name
poetry run pytest -k test_subdomain_enum

# Run with coverage
poetry run pytest --cov=bbot --cov-report=term-missing
```

CI runs on every push and PR across multiple Python versions and OSes — see `.github/workflows/tests.yml` and `.github/workflows/distro_tests.yml`. Please make sure your PR has green CI before requesting review.

If you're adding a new module, please add at least one targeted test in `bbot/modules/<name>/test.py` (see existing modules for examples).

## Submitting a Pull Request

1. **Create a topic branch** off `dev`:
   ```bash
   git fetch upstream
   git checkout -b feat/<short-description> upstream/dev
   ```
   Use a descriptive branch name: `feat/<thing>`, `fix/<thing>`, `docs/<thing>`, or `ci/<thing>`.

2. **Make focused commits** with clear messages. Conventional-Commits-style subjects are encouraged:
   ```
   feat: add shuffledns module
   fix: handle empty DNS responses in dnsresolve
   docs: clarify --strict-scope usage
   ci: run pytest on push
   ```

3. **Push to your fork**:
   ```bash
   git push origin feat/<short-description>
   ```

4. **Open a Pull Request** against `blacklanternsecurity/bbot:dev` and include:
   - A short summary of **what** changed and **why**.
   - The issue number it fixes (e.g. `Closes #123`).
   - A **Test Plan** checklist (commands you ran, screenshots/log snippets).
   - Any **breaking changes** or new dependencies called out explicitly.

5. **Respond to review** — be patient, address feedback in new commits (don't force-push during review), and re-request review once you've pushed.

## Writing a New Module

New modules are the most common contribution. A module is just a Python class that subclasses `bbot.modules.base.BaseModule`. A good starting point:

1. Look at a small existing module (e.g. `bbot/modules/badsecrets/`) as a template.
2. Place your module under `bbot/modules/<your_module>/` with at minimum:
   - `__init__.py` — exports your module class.
   - `<your_module>.py` — implementation.
   - `test.py` — at least one unit test.
3. Register it in the appropriate `bbot/modules/<category>.yml` (or wherever the project's module registry expects).
4. Add an entry to the docs (`docs/scanning/modules/<your_module>.md`) describing flags, dependencies, and example usage.
5. Open a PR — maintainers will help with categorization, flag review, and tests.

For **output modules**, the entry point is `bbot.modules.output.base.BaseOutputModule`. For **helpers**, see `bbot/modules/helpers/base.py`.

## Release Process

Releases are cut by the maintainers from the `dev` branch. Versions follow [Semantic Versioning](https://semver.org/). Changelog entries are aggregated from merged PR titles.

---

Thanks again for contributing to BBOT. If you have any questions, drop into the [Discord](https://discord.com/invite/PZqkgxu5SA) or open a discussion on GitHub.
