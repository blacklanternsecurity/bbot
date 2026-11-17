# AGENTS.md

BBOT is a recursive, modular OSINT and attack surface scanner. Modules consume and emit events. The scanner routes them by scope distance.

## Core Principles

### Modularity Principle

When writing a BBOT module, make sure all module-specific code lives in the module itself. Don't hard-code module-specific things in core or in helpers.

### DRY Principle

Don't Repeat Yourself -- and interpret this broadly. If two pieces of code aren't identical but follow a similar enough pattern that they could be generalized, they should be. Extract shared logic into a common abstraction rather than duplicating the pattern. Usually this means creating a shared helper, or a shared module template in `bbot/modules/templates`. When you notice structural similarity, unify it.

### Engineering Principle

Every system that is implemented must be implemented properly. No hacks, no hardcoding, no shortcuts. If we implement one of something, we build a proper system for it. It's okay to take a step back from the current task, in order to do things right. This relates directly to the Modularity Principle above.

### Testing Principle

BBOT has extremely thorough tests, including **one or more individual tests for each module, with no exceptions**. This is critical to maintaining stability in a recursive tool, which by its nature flirts with race conditions and infinite loops. If you add a module, you write a test. If you change a module, you make sure its test still passes.

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

# the full suite, or a comma-separated subset
./bbot/test/run_tests.sh
./bbot/test/run_tests.sh robots,sslcert
```

Every module has at least one test of its own in `bbot/test/test_step_2/module_tests/`, named `test_module_<name>.py`. [docs/dev/tests.md](docs/dev/tests.md) covers how one is structured and how to mock HTTP and DNS.

### Never hardcode a port or URL in a test

`ModuleTestBase` starts a local HTTP server for every test, and the test registers canned responses on it with `module_test.set_expect_requests()`. A web module's test points `targets` at that server, which is why so many tests contain a `127.0.0.1` URL: it's the fixture, not a real host.

Its port is no longer fixed. The suite runs under `pytest -n`, and `bbot/test/worker.py` offsets every base port by the worker index so the workers don't collide on one socket: the server is on 8888 under `gw0`, 8988 under `gw1`. So `targets = ["http://127.0.0.1:8888"]` names `gw0`'s server rather than your own, and the test reaches another worker's server or nothing at all, depending on how pytest distributed that run.

Use `HTTPSERVER_URL`. It is `http://127.0.0.1:<this worker's port>`, built at import time from the same offset the fixture uses, so it always resolves to the server the test is actually talking to:

```python
from bbot.test.worker import HTTPSERVER_URL


class TestMyModule(ModuleTestBase):
    targets = [HTTPSERVER_URL]
```

`/tmp/.bbot_test` has the same problem, since the first worker to finish deletes it. `BBOT_TEST_DIR` is the per-worker equivalent.

| Constant | What it is |
|---|---|
| `HTTPSERVER_URL` | `http://127.0.0.1:<port>`, the usual value for `targets` |
| `HTTPSERVER_SSL_URL` | the HTTPS equivalent |
| `HTTPSERVER_PORT`, `HTTPSERVER_SSL_PORT` | the bare ports, for building a URL or a regex |
| `HTTPSERVER_HOSTPORT`, `HTTPSERVER_SSL_HOSTPORT` | `127.0.0.1:<port>`, no scheme |
| `LOCALHOST_URL`, `LOCALHOST_SSL_URL`, `LOCALHOST_HOSTPORT` | the `localhost` spellings, for when the Host header is what's under test |
| `HTTPSERVER_PORT_ALT` | a second port inside the same worker's block |
| `HTTPSERVER_ALLINTERFACES_PORT` | the `0.0.0.0` listener |
| `FASTAPI_URL`, `FASTAPI_PORT` | the FastAPI test app |
| `WEBSOCKET_PORT` | the websocket test server |
| `BBOT_TEST_DIR`, `BBOT_TEST_DIR_NAME` | the per-worker BBOT home, and its basename |

## Branches

`stable` is the default branch and holds production releases. `dev` is active development. Branch from `dev`, and target `dev` with almost every pull request. See [git.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/git.md) for the rest, and [docs/contribution.md](docs/contribution.md) for what BBOT expects of a contribution.

## AI Use Disclosure

Use of AI is not prohibited -- and in many cases, encouraged. However, when reviewing a PR, it is helpful for the reviewer to know the extent to which AI was used, and which model.
Please add a small section at the bottom of the PR with the header: `### AI Use Disclosure`, followed by the following information:

* Extent of the AI use. For example, was this fully autonomous by the AI, or was it a collaborative back-and-forth, or did the user just use the AI to review their work, etc.
* Model Used

This should only apply to external contributors, not members of the blacklanternsecurity organization.

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
| [docs/contribution.md](docs/contribution.md) | Opening a pull request against BBOT |

Shared module patterns go in `bbot/modules/templates/`.

## Architecture Overview

### How a Scan Works

BBOT is an async, recursive OSINT tool. A scan starts with **seed events** (targets) and passes them through a pipeline of **modules**. Each module watches for specific event types, processes them, and may emit new events, which re-enter the pipeline at the top. This continues until no module has anything left to do.

Every event takes the same path:

1. **`ScanIngress`** (`bbot/scanner/manager.py`) is always first. It dedupes the event, checks it against the blacklist, and sets its scope distance.
2. **Intercept modules** (`bbot/modules/internal/`) run in sequence, each one's outgoing queue wired to the next one's incoming queue. They tag and modify events before any normal module sees them, and can drop one outright. `dnsresolve` resolves hosts, `cloudcheck` tags cloud and CDN providers, `excavate` pulls new events out of HTTP response bodies.
3. **`ScanEgress`** (`bbot/scanner/manager.py`) is always last in that chain. It decides what is internal versus output-worthy (report distance, omitted event types, special URLs), runs any `abort_if` callback, and resurrects parent events so the discovery chain stays intact.
4. **Scan modules** then get the event in parallel, each filtered by its own `watched_events`. Anything they emit goes back to step 1.
5. **Output modules** (`bbot/modules/output/`) get it too, and write it out as json, csv, neo4j, and so on.

The intercept chain is ordered by `priority`: `ScanIngress` is -99, `ScanEgress` is 99, everything else sorts between them.

### Events

Events are the currency of BBOT. Every piece of data -- a hostname, IP, URL, open port, finding -- is an event. Events have:

- **type**: `DNS_NAME`, `IP_ADDRESS`, `URL`, `OPEN_TCP_PORT`, `HTTP_RESPONSE`, `FINDING`, `EMAIL_ADDRESS`, etc.
- **data**: the actual data (a string, dict, etc.)
- **parent**: the event that led to this one (forming a discovery chain)
- **scope_distance**: how many hops from the original target (0 = in-scope)
- **tags**: metadata the scanner and modules attach as an event moves through the pipeline
- **module**: which module discovered it

Event classes, their data validators, and the tags they set are in `bbot/core/event/base.py`.

### Scope Distance

Scope distance tracks how far an event is from the original target:
- `0` = explicitly in-scope (matches target or discovered in-scope)
- `1` = one hop away (e.g. a hostname found in an SSL cert of an in-scope host)
- `2+` = further away

The scan's `scope.search_distance` (default 0) controls how far modules are allowed to look. A module's `scope_distance_modifier` adjusts this per-module.

### Helpers

BBOT has a helper for almost everything: HTTP requests, DNS resolution, domain and URL parsing, port strings, wordlists, temp files, subprocesses, regexes. **Please use them.** They are reachable from `self.helpers` inside any module, and most of what a new module needs already exists, so look before writing utility code of your own. The one thing worth knowing up front: run subprocesses with `self.run_process()` / `self.run_process_live()` rather than the raw helpers, so the module's processes are tracked and killed with it.

The full list is generated from the source under [docs/dev/helpers/](docs/dev/helpers/index.md), split by area (command, dns, web, interactsh, wordcloud, misc). `bbot/core/helpers/misc.py` holds the long tail of small utilities and is worth skimming once.
