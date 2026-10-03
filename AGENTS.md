# AGENTS.md

BBOT is a recursive, modular OSINT and attack surface scanner. Modules consume and emit events. The scanner routes them by scope distance.

## Toolchain

| Concern | This repository |
|---|---|
| Language | Python, `requires-python` in pyproject.toml |
| Package manager | uv |
| Lint and format | ruff, pinned in pyproject.toml |
| Tests | pytest, plugins in the `dev` group of pyproject.toml |

## Setup

```bash
uv sync --group dev && uv run pre-commit install
```

## Tests

```bash
uv run pytest
uv run pytest bbot/test/test_step_2/module_tests/test_module_robots.py
```

## Standards

Org-wide, in [blacklanternsecurity/.github/standards](https://github.com/blacklanternsecurity/.github/tree/main/standards). Read the one your task touches, not all of them.

| Document | Read it when |
|---|---|
| [principles.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/principles.md) | Always |
| [toolchain.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/toolchain.md) | Touching dependencies, linting, formatting, or language versions |
| [git.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/git.md) | Branching, commit messages, opening or reviewing a pull request |
| [rfc.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/rfc.md) | A change needs agreement before work starts, or an RFC is ending |
| [testing.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/testing.md) | Writing or changing tests, or anything that has them |
| [ci.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/ci.md) | Touching a workflow, an action pin, or a permissions block |
| [releases.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/releases.md) | Versioning, tagging, or publishing |
| [repository-setup.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/repository-setup.md) | Creating a repository, or auditing one |

Never restate a standard here. If this file and a standard disagree, the standard wins and this file is the bug.

## Repository specifics

| Document | Read it when |
|---|---|
| [docs/dev/module_howto.md](docs/dev/module_howto.md) | Writing or changing a module |
| [bbot/modules/base.py](bbot/modules/base.py) | Looking up a module attribute, its default, or a `BaseModule` method |
| [docs/dev/tests.md](docs/dev/tests.md) | Writing a module test, mocking HTTP or DNS |
| [docs/dev/helpers/index.md](docs/dev/helpers/index.md) | Before writing utility code, `self.helpers` likely has it |
| [docs/dev/architecture.md](docs/dev/architecture.md) | Touching the scanner, queues, or event flow |
| [docs/dev/dev_environment.md](docs/dev/dev_environment.md) | Setting up from a fresh fork |

Shared module patterns go in `bbot/modules/templates/`.
