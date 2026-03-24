# BBOT Developer Guide

## Core Principles

### Modularity Principle
When writing a BBOT module, make sure all module-specific code lives in the module itself. Don't hard-code module-specific things in core or in helpers.

### DRY Principle
Don't Repeat Yourself -- and interpret this broadly. If two pieces of code aren't identical but follow a similar enough pattern that they could be generalized, they should be. Extract shared logic into a common abstraction rather than duplicating the pattern. Usually this means creating a shared helper, or a shared module template in `bbot/modules/templates`. When you notice structural similarity, unify it.

### Engineering Principle
Every system that is implemented must be implemented properly. No hacks, no hardcoding, no shortcuts. If we implement one of something, we build a proper system for it. It's okay to take a step back from the current task, in order to do things right. This relates directly to the Modularity Principle above.

### Testing Principle
BBOT has extremely thorough tests, including **one or more individual tests for each module, with no exceptions**. This is critical to maintaining stability in a recursive tool, which by its nature flirts with race conditions and infinite loops. If you add a module, you write a test. If you change a module, you make sure its test still passes.

---

## Tooling

- **Package manager**: [uv](https://docs.astral.sh/uv/)
- **Linter/formatter**: [ruff](https://docs.astral.sh/ruff/) (pinned to 0.15.2)
- **Test framework**: [pytest](https://docs.pytest.org/) with pytest-asyncio
- **Python**: 3.10 - 3.14

---

## Dev Environment Setup

```bash
# 1. Fork and clone
git clone git@github.com:<you>/bbot.git
cd bbot

# 2. Switch to dev branch, then create a feature branch
git checkout dev
git checkout -b my-feature

# 3. Install uv (if you haven't already)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 4. Install all dependencies (including dev)
uv sync --group dev

# 5. Install pre-commit hooks (ruff, file checks, etc.)
uv run pre-commit install

# 6. Activate the virtualenv
source .venv/bin/activate

# 7. Verify
bbot --help
```

### Running Tests

```bash
# Run the full suite
./bbot/test/run_tests.sh

# Run specific module tests
./bbot/test/run_tests.sh robots,sslcert

# Run a single test file directly
pytest bbot/test/test_step_2/module_tests/test_module_robots.py -x -vv
```

### Linting

```bash
ruff check          # lint
ruff format          # auto-format
ruff format --check  # verify formatting without changes
```

### Git Workflow

- `stable` - production releases
- `dev` - active development, PR target
- Feature branches are created from `dev`

---

## Architecture Overview

### How a Scan Works

BBOT is an async, recursive OSINT tool. A scan starts with **seed events** (targets) and passes them through a pipeline of **modules**. Each module watches for specific event types, processes them, and may emit new events, which feed back into the pipeline. This continues until no module has anything left to do.

```
                     Seeds (targets)
                          |
                          v
                   +--------------+
                   | ScanIngress  |  dedup, blacklist, scope check
                   +--------------+
                          |
                          v
                   +--------------+
                   |  Intercept   |  dns, cloud tagging
                   |   Modules    |  (modify/tag events before distribution)
                   +--------------+
                          |
                          v
                   +--------------+
                   |  ScanEgress  |  scope filtering, graph management
                   +--------------+
                          |
                          v
              +-----------+-----------+
              |           |           |
           Module A    Module B    Module C   ...
              |           |           |
              +-----------+-----------+
                          |
                          v
                   Output Modules (json, csv, neo4j, ...)
```

### Events

Events are the currency of BBOT. Every piece of data -- a hostname, IP, URL, open port, finding -- is an event. Events have:

- **type**: `DNS_NAME`, `IP_ADDRESS`, `URL`, `OPEN_TCP_PORT`, `HTTP_RESPONSE`, `FINDING`, `VULNERABILITY`, `EMAIL_ADDRESS`, etc.
- **data**: the actual data (a string, dict, etc.)
- **parent**: the event that led to this one (forming a discovery chain)
- **scope_distance**: how many hops from the original target (0 = in-scope)
- **tags**: metadata like `in-scope`, `affiliate`, `cloud-azure`, `open-port`, etc.
- **module**: which module discovered it

### Scope Distance

Scope distance tracks how far an event is from the original target:
- `0` = explicitly in-scope (matches target or discovered in-scope)
- `1` = one hop away (e.g. a hostname found in an SSL cert of an in-scope host)
- `2+` = further away

The scan's `scope.search_distance` (default 0) controls how far modules are allowed to look. A module's `scope_distance_modifier` adjusts this per-module.

### Helpers

BBOT has a helper for almost everything. **Please use them.** They're accessible via `self.helpers` inside any module.

Key helpers:

| Helper | What it does |
|--------|-------------|
| `self.helpers.request(url)` | Make an HTTP request (with retries, SSL handling, etc.) |
| `self.helpers.resolve(host)` | DNS resolution |
| `self.helpers.is_ip(s)` | Check if string is an IP |
| `self.helpers.is_dns_name(s)` | Check if string is a hostname |
| `self.helpers.split_domain(host)` | Split into subdomain + root domain |
| `self.helpers.domain_parents(domain)` | Get all parent domains |
| `self.helpers.make_netloc(host, port)` | Format `host:port` (handles IPv6) |
| `self.helpers.parent_domain(domain)` | Get immediate parent domain |
| `self.helpers.beautifulsoup(html, parser)` | Parse HTML |
| `self.helpers.validators.validate_host(h)` | Validate and normalize a hostname |
| `self.helpers.tempfile(data, pipe=False)` | Create a temp file with content |
| `self.helpers.run(command)` | Run a shell command |
| `self.helpers.run_live(command)` | Run a shell command, stream output |
| `self.helpers.as_completed(tasks)` | Async iteration of completed tasks |
| `self.helpers.wordlist(url_or_path)` | Download/cache a wordlist |
| `self.helpers.rand_string(n)` | Random string of length n |
| `self.helpers.regexes.email_regex` | Pre-compiled email regex |
| `self.helpers.add_get_params(url, params)` | Add query params to a URL |
| `self.helpers.quote(s)` | URL-encode a string |
| `self.helpers.make_ip_type(s)` | Convert string to `ipaddress` object |
| `self.helpers.parse_port_string(s)` | Parse port range string (e.g. `"80,443,8000-9000"`) |
| `self.helpers.top_tcp_ports(n)` | Get top N TCP ports |

There are hundreds more in `bbot/core/helpers/misc.py`. Browse them before writing utility code yourself.

---

## Writing a Module

### Quick Start

1. Create `bbot/modules/my_module.py`
2. Define a class that inherits from `BaseModule`
3. Set `watched_events`, `produced_events`, `flags`, and `meta`
4. Implement `handle_event()`
5. Create `bbot/test/test_step_2/module_tests/test_module_my_module.py`

Here's a minimal module:

```python
from bbot.modules.base import BaseModule


class my_module(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum"]
    meta = {
        "description": "Query example.com for email addresses",
        "created_date": "2025-01-01",
        "author": "@you",
    }

    async def handle_event(self, event):
        url = f"https://api.example.com/lookup?domain={event.data}"
        r = await self.helpers.request(url)
        if r and r.status_code == 200:
            for email in r.json().get("emails", []):
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=event,
                    context=f"{{module}} queried example.com and found {{event.type}}: {{event.data}}",
                )
```

And its test:

```python
from .base import ModuleTestBase


class TestMyModule(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.example.com/lookup?domain=blacklanternsecurity.com",
            json={"emails": ["info@blacklanternsecurity.com"]},
        )

    def check(self, module_test, events):
        assert any(
            e.data == "info@blacklanternsecurity.com" and e.type == "EMAIL_ADDRESS"
            for e in events
        ), "Failed to find email"
```

### Module Lifecycle

```
setup()  -->  handle_event() (called many times)  -->  finish()  -->  report()  -->  cleanup()
```

1. **`setup()`** - one-time initialization (validate config, download data, check API keys)
2. **`handle_event(event)`** - called for each matching event
3. **`finish()`** - called when the scan is finishing; can still emit events
4. **`report()`** - called once after finish; for summary output
5. **`cleanup()`** - called last; close files, delete temp data; **cannot** emit events

---

### Module Attributes Reference

#### Event Configuration

##### `watched_events` (list)
Event types this module wants to process. The module's `handle_event()` is only called for these types.

```python
# sslcert.py - watches for open ports to grab SSL certs from
watched_events = ["OPEN_TCP_PORT"]

# newsletters.py - watches HTTP responses to scan HTML
watched_events = ["HTTP_RESPONSE"]

# json.py (output module) - watches everything
watched_events = ["*"]
```

##### `produced_events` (list)
Event types this module may emit. Used for dependency resolution and documentation.

```python
# sslcert.py - can discover hostnames and emails from certificates
produced_events = ["DNS_NAME", "EMAIL_ADDRESS"]

# portscan.py - finds open ports
produced_events = ["OPEN_TCP_PORT"]
```

##### `flags` (list)
Tags that describe the module's behavior. Must include at least one activity flag (`passive` or `active`). Must also include `safe`, `loud`, or `invasive` (or a combination of `loud` and `invasive`).

Common flags:
- `passive` / `active` - whether the module touches the target directly
- `safe` - non-intrusive and non-destructive
- `loud` - generates a large amount of network traffic
- `invasive` - intrusive or potentially destructive
- `subdomain-enum` - participates in subdomain enumeration
- `web` - basic web scanning
- `email-enum` - email discovery

```python
# crt.py - queries a third-party API, never touches the target
flags = ["subdomain-enum", "passive"]

# sslcert.py - connects directly to target ports
flags = ["affiliates", "subdomain-enum", "email-enum", "active", "web"]
```

##### `meta` (dict)
Module metadata. Must include `description`, `created_date`, and `author`. Set `auth_required: True` if the module needs an API key.

```python
meta = {
    "description": "Query crt.sh (certificate transparency) for subdomains",
    "created_date": "2022-05-13",
    "author": "@TheTechromancer",
}

# For API-key modules:
meta = {"description": "Query API for subdomains", "auth_required": True}
```

---

#### Options

##### `options` / `options_desc` (dict)
User-configurable settings. Access them via `self.config.get("option_name")`.

```python
# robots.py - configurable parsing options
options = {"include_sitemap": False, "include_allow": True, "include_disallow": True}
options_desc = {
    "include_sitemap": "Include 'sitemap' entries",
    "include_allow": "Include 'Allow' Entries",
    "include_disallow": "Include 'Disallow' Entries",
}

# In handle_event():
if self.config.get("include_sitemap") is True:
    ...
```

```python
# sslcert.py - timeout and behavior options
options = {"timeout": 5.0, "skip_non_ssl": True}
options_desc = {"timeout": "Socket connect timeout in seconds", "skip_non_ssl": "Don't try common non-SSL ports"}
```

---

#### Scope & Filtering

##### `scope_distance_modifier` (int or None) -- default: `0`
Controls which events the module accepts based on how far they are from the target.

- `0` (default) - accept events up to the scan's configured search distance
- `1` - accept events up to search distance + 1
- `None` - accept all events regardless of distance

```python
# sslcert.py - looks one hop beyond normal scope, because certificate names
# found on in-scope hosts often reveal related infrastructure
scope_distance_modifier = 1
```

##### `in_scope_only` (bool) -- default: `False`
Only accept events that are explicitly in-scope (distance == 0). More restrictive than `scope_distance_modifier = 0`.

```python
# robots.py - only fetch robots.txt for in-scope hosts
in_scope_only = True
```

##### `target_only` (bool) -- default: `False`
Only accept the initial target/seed events. Useful for modules that should only run once against the original targets.

##### `accept_seeds` (bool) -- default: `True` for passive, `False` for active
Whether to process seed events (the initial targets provided to the scan).

##### `accept_url_special` (bool) -- default: `False`
Whether to accept "special" URLs (e.g. JavaScript files) that are not normally distributed to web modules.

```python
# httpx.py - needs to process all URLs including special ones
accept_url_special = True
```

---

#### Deduplication

##### `accept_dupes` (bool) -- default: `False`
Whether to accept the same event more than once. Most modules should leave this `False`.

```python
# Output modules set this True because they need to see every event
accept_dupes = True
```

##### `suppress_dupes` (bool) -- default: `True`
Whether to suppress duplicate *outgoing* events. Prevents the same event from being emitted twice.

##### `per_host_only` (bool) -- default: `False`
Only process one event per unique host. After processing `1.2.3.4`, skip any future events for `1.2.3.4`.

##### `per_hostport_only` (bool) -- default: `False`
Only process one event per unique host:port combination.

```python
# robots.py - only fetch robots.txt once per host:port
per_hostport_only = True
```

##### `per_domain_only` (bool) -- default: `False`
Only process one event per unique root domain. After processing `www.example.com`, skip `api.example.com`.

```python
# emailformat.py - one API query per domain is enough
per_domain_only = True
```

##### `_incoming_dedup_hash(self, event)` -- override for custom dedup
Override this to define custom deduplication logic. Return a hash (int) or `(hash, reason_string)`.

```python
# securitytxt.py - dedupe by parent domain so we only check security.txt once
# per parent domain, not once per subdomain
def _incoming_dedup_hash(self, event):
    parent_domain = self.helpers.parent_domain(event.data)
    return hash(parent_domain), "already processed parent domain"
```

```python
# subdomain_enum.py template - dedupe by highest or lowest parent domain
def _incoming_dedup_hash(self, event):
    return hash(self.make_query(event)), f"dedup_strategy={self.dedup_strategy}"
```

---

#### Concurrency & Batching

##### `_module_threads` (int) -- default: `1`
How many `handle_event()` calls can run concurrently. Increase this for I/O-bound modules.

```python
# sslcert.py - connects to many hosts in parallel
_module_threads = 25
```

##### `_batch_size` (int) -- default: `1`
When > 1, events are collected into batches and passed to `handle_batch(*events)` instead of `handle_event()`. Useful for tools that work better with bulk input.

```python
# portscan.py - masscan is most efficient with all targets at once
batch_size = 1000000

async def handle_batch(self, *events):
    targets, correlator = await self.make_targets(events, self.syn_scanned)
    async for ip, port, parent_event in self.masscan(targets, correlator):
        await self.emit_open_port(ip, port, parent_event)
```

##### `_shuffle_incoming_queue` (bool) -- default: `True`
Whether to randomize the order of incoming events. Set to `False` when order matters.

```python
# portscan.py - processes all events together, order doesn't matter but
# we disable shuffle because batch_size is huge
_shuffle_incoming_queue = False
```

---

#### Dependencies

##### `deps_pip` (list)
Python packages to install.

```python
# sslcert.py
deps_pip = ["pyOpenSSL~=25.3.0"]
```

##### `deps_apt` (list)
System packages to install.

```python
# sslcert.py
deps_apt = ["openssl"]
```

##### `deps_modules` (list)
Other BBOT modules that must be enabled for this module to work.

##### `deps_shell` (list)
Shell commands to run for installation (uses Ansible's `shell` module).

##### `deps_ansible` (list)
Ansible tasks for complex dependency installation (downloading binaries, etc.).

```python
# fingerprintx.py - downloads a Go binary
deps_ansible = [
    {
        "name": "Download fingerprintx",
        "unarchive": {
            "src": "https://github.com/.../fingerprintx_{version}_{platform}_{arch}.tar.gz",
            "include": "fingerprintx",
            "dest": "#{BBOT_TOOLS}",
            "remote_src": True,
        },
    },
]
```

---

#### Priority & Queue

##### `_priority` (int) -- default: `3`
Module priority from 1 (highest) to 5 (lowest). Lower-priority modules get events first.

```python
# sslcert.py - runs early because other modules depend on the hostnames it discovers
_priority = 2
```

##### `_qsize` (int) -- default: `1000`
Outgoing event queue size. A smaller queue creates backpressure that helps with rate limiting.

```python
# subdomain_enum.py template - small queue to combat API rate limiting
_qsize = 10
```

##### `_preserve_graph` (bool) -- default: `False`
Accept duplicate events that are needed for complete event chain construction. Only used by output modules.

```python
# json.py - needs complete event chains for accurate output
_preserve_graph = True
```

##### `_stats_exclude` (bool) -- default: `False`
Exclude this module from scan statistics. Used by output and report modules.

##### `_disable_auto_module_deps` (bool) -- default: `False`
Prevent BBOT from automatically enabling dependency modules. For example, if your module watches `URL` events, BBOT normally auto-enables `httpx`. Set this to `True` to prevent that.

---

### Key Methods

#### `handle_event(self, event)` -- the core method

Called once for each matching event. This is where your module does its work.

```python
# robots.py - fetch and parse robots.txt
async def handle_event(self, event):
    host = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}/"
    url = f"{host}robots.txt"
    result = await self.helpers.request(url)
    if result:
        body = result.text
        if body:
            for line in body.split("\n"):
                if line.startswith("Disallow:"):
                    path = line.split(": ", 1)[1].lstrip("/")
                    await self.emit_event(
                        f"{host}{path}",
                        "URL_UNVERIFIED",
                        parent=event,
                        tags=["spider-danger"],
                    )
```

#### `handle_batch(self, *events)` -- bulk processing

Used when `_batch_size > 1`. Receives multiple events at once.

```python
# portscan.py - bulk port scanning with masscan
async def handle_batch(self, *events):
    targets, correlator = await self.make_targets(events, self.syn_scanned)
    async for ip, port, parent_event in self.masscan(targets, correlator):
        await self.emit_open_port(ip, port, parent_event)
```

#### `filter_event(self, event)` -- custom event filtering

Called before `handle_event()`. Return `True` to accept, `False` to reject, or `(False, "reason")` to reject with a logged reason.

```python
# sslcert.py - skip ports that don't typically use SSL
async def filter_event(self, event):
    if self.skip_non_ssl and event.port in self.non_ssl_ports:
        return False, f"Port {event.port} doesn't typically use SSL"
    return True
```

```python
# subdomain_enum.py template - reject wildcards and cloud resources
async def filter_event(self, event):
    query = self.make_query(event)
    is_wildcard = await self._is_wildcard(query)
    if self.reject_wildcards and is_wildcard:
        return False, "Event is a wildcard domain"
    return True, ""
```

#### `setup(self)` -- one-time initialization

Return values:
- `True` -- success
- `(True, "message")` -- success with message
- `None` or `(None, "message")` -- **soft fail**: module is disabled, scan continues
- `False` or `(False, "message")` -- **hard fail**: scan aborts

```python
# portscan.py - validates config, checks masscan, checks IPv6 support
async def setup(self):
    self.top_ports = self.config.get("top_ports", 100)
    self.rate = self.config.get("rate", 300)
    self.ports = self.config.get("ports", "")
    if self.ports:
        try:
            self.helpers.parse_port_string(self.ports)
        except ValueError as e:
            return False, f"Error parsing ports '{self.ports}': {e}"
    # ...
    return True
```

```python
# subdomain_enum_apikey template - soft-fail if API key is missing
async def setup(self):
    await super().setup()
    return await self.require_api_key()
    # Returns (None, "No API key set") if missing, disabling the module
```

#### `finish(self)` -- called when scan is finishing

Can still emit events. May be called multiple times if new activity is detected.

#### `report(self)` -- summary output

Called once after `finish()`. Use for generating tables or summary data.

```python
# asn.py - output ASN statistics
async def report(self):
    self.log_table(table_data, headers=["ASN", "Subnet", "Count"], table_name="asns")
```

#### `cleanup(self)` -- resource cleanup

Called once at the very end. Close files, delete temp files. **Cannot emit events.**

```python
# json.py
async def cleanup(self):
    if getattr(self, "_file", None) is not None:
        with suppress(Exception):
            self.file.close()
```

```python
# portscan.py
async def cleanup(self):
    with suppress(Exception):
        self.exclude_file.unlink()
```

---

### Emitting Events

#### `emit_event(data, event_type, parent, **kwargs)`

Creates and queues an event for processing by other modules.

```python
# Simple string event
await self.emit_event("sub.example.com", "DNS_NAME", parent=event)

# With context (used for discovery chain documentation)
await self.emit_event(
    "sub.example.com",
    "DNS_NAME",
    parent=event,
    context=f"{{module}} queried crt.sh and found {{event.type}}: {{event.data}}",
)

# With tags
await self.emit_event(url, "URL_UNVERIFIED", parent=event, tags=["spider-danger"])

# FINDING event (dict data)
await self.emit_event(
    {
        "host": str(event.host),
        "description": "Found something interesting",
        "url": event.data["url"],
        "severity": "HIGH",
    },
    "FINDING",
    parent=event,
)
```

#### `make_event(data, event_type, parent, **kwargs)`

Creates an event without emitting it. Useful when you need to inspect or modify it first.

```python
ssl_event = self.make_event(hostname, "DNS_NAME", parent=event, raise_error=True)
if ssl_event:
    await self.emit_event(ssl_event, tags=["affiliate"])
```

---

### API Helpers

#### `api_request(url, **kwargs)`

HTTP request with automatic retry, rate-limit handling (429), API key cycling, and failure tracking. After too many failures, the module enters error state.

```python
r = await self.api_request("https://api.example.com/search?q=test")
if r and r.status_code == 200:
    data = r.json()
```

#### `require_api_key()`

Validates that an API key is configured. Call in `setup()`.

```python
async def setup(self):
    return await self.require_api_key()
```

#### `api_page_iter(url, page_size=100, **kwargs)`

Async generator for paginated API results. URL can contain `{page}`, `{page_size}`, and `{offset}` placeholders.

```python
async for page in self.api_page_iter(
    "https://api.example.com/search?q=test&page={page}&limit={page_size}"
):
    if not page.get("results"):
        break
    for result in page["results"]:
        await self.emit_event(result["hostname"], "DNS_NAME", parent=event)
```

---

### Running External Processes

```python
# Run a command and get the result
result = await self.run_process(["nmap", "-p", "22,80", target])
if result.returncode == 0:
    output = result.stdout

# Stream output line-by-line (for long-running tools)
async for line in self.run_process_live(["masscan", "-oJ", "-", ...]):
    data = json.loads(line)
```

---

### Logging

```python
self.debug("Low-level detail")        # only visible with -d flag
self.verbose("Useful but not critical") # visible with -v flag
self.info("Standard info")
self.success("Something good happened") # green
self.warning("Something concerning")    # orange
self.error("Something failed")          # red

# "Huge" variants: entire line in bold color
self.hugesuccess("Major discovery!")
self.hugewarning("Major concern!")
```

---

### Templates

For common patterns, inherit from a template instead of `BaseModule` directly. Templates live in `bbot/modules/templates/`:

- **`subdomain_enum`** - passive subdomain enumeration via free API. Handles dedup, wildcard rejection, query building.
- **`subdomain_enum_apikey`** - same as above but requires an API key.
- **`shodan`** - Shodan API integration.
- **`github`** - GitHub API integration.
- **`censys`** - Censys API integration.
- **`bucket`** - Cloud storage bucket enumeration.
- **`webhook`** - Webhook output.

Example: `crt.py` inherits from `subdomain_enum` and only needs to override the request/parse logic:

```python
from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt(subdomain_enum):
    flags = ["subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains",
        "created_date": "2022-05-13",
        "author": "@TheTechromancer",
    }
    base_url = "https://crt.sh"

    async def request_url(self, query):
        params = {"q": f"%.{query}", "output": "json"}
        url = self.helpers.add_get_params(self.base_url, params).geturl()
        return await self.api_request(url, timeout=self.http_timeout + 30)

    async def parse_results(self, r, query):
        results = set()
        for cert_info in r.json():
            domain = cert_info.get("name_value")
            if domain:
                for d in domain.splitlines():
                    results.add(d.lower())
        return results
```

---

### Module Types

#### Scan Modules (default)
Normal modules that watch events and produce new ones. This is what you'll write 95% of the time.

#### Output Modules
Inherit from `BaseOutputModule`. Receive all events and write them somewhere.

```python
from bbot.modules.output.base import BaseOutputModule

class my_output(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Custom output"}
    _preserve_graph = True  # maintain complete event chains

    async def handle_event(self, event):
        # write event to file, database, API, etc.
        ...
```

Output modules automatically get:
- `accept_dupes = True`
- `scope_distance_modifier = None` (see all events)
- `_stats_exclude = True`

#### Internal Modules
Inherit from `BaseInternalModule`. System-level modules that aren't exposed to users.

#### Intercept Modules
Inherit from `BaseInterceptModule`. Special high-priority modules that can modify or reject events before they reach normal modules. Used for DNS resolution, cloud detection, etc. You probably don't need to write one.

---

### Writing Tests

Every module needs a test in `bbot/test/test_step_2/module_tests/`. The test file must be named `test_module_<name>.py`.

Test classes inherit from `ModuleTestBase` and follow this pattern:

```python
from .base import ModuleTestBase


class TestMyModule(ModuleTestBase):
    # Optional: override targets (default: ["blacklanternsecurity.com"])
    targets = ["http://127.0.0.1:8888"]

    # Optional: override which modules are enabled
    modules_overrides = ["httpx", "my_module"]

    # Optional: override config
    config_overrides = {"modules": {"my_module": {"some_option": True}}}

    async def setup_before_prep(self, module_test):
        """Called BEFORE the scan is prepared. Set up HTTP mocks here."""
        pass

    async def setup_after_prep(self, module_test):
        """Called AFTER the scan is prepared. Modify modules, add mocks here."""
        # Mock an HTTP response
        module_test.httpx_mock.add_response(
            url="https://api.example.com/lookup?domain=blacklanternsecurity.com",
            json={"results": ["sub.blacklanternsecurity.com"]},
        )

        # Mock DNS
        await module_test.mock_dns({
            "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
        })

        # Mock an HTTP server response
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/robots.txt"},
            respond_args={"response_data": "Disallow: /secret/"},
        )

    def check(self, module_test, events):
        """Verify the scan produced the expected events."""
        assert any(
            e.data == "sub.blacklanternsecurity.com" and e.type == "DNS_NAME"
            for e in events
        ), "Failed to find subdomain"
```

The test lifecycle runs:
1. `setup_before_prep()` - set up mocks
2. Scan `_prep()` - loads modules, config
3. `setup_after_prep()` - modify scan state
4. Scan runs and collects events
5. `check()` - your assertions

### Test Utilities

- **`module_test.httpx_mock`** - mock HTTP responses (from pytest-httpx)
- **`module_test.httpserver`** - real HTTP server on port 8888
- **`module_test.httpserver_ssl`** - real HTTPS server on port 9999
- **`module_test.mock_dns(data)`** - mock DNS responses
- **`module_test.mock_interactsh(name)`** - mock out-of-band interactions
- **`module_test.module`** - reference to the module instance being tested
- **`module_test.scan`** - reference to the Scanner instance

Real example -- `test_module_robots.py`:

```python
class TestRobots(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "robots"]
    config_overrides = {"modules": {"robots": {"include_sitemap": True}}}

    async def setup_after_prep(self, module_test):
        robots = "Allow: /allow/\nDisallow: /disallow/\nSitemap: http://127.0.0.1:8888/sitemap.txt"
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/robots.txt"},
            respond_args={"response_data": robots},
        )

    def check(self, module_test, events):
        assert any(e.data == "http://127.0.0.1:8888/allow/" for e in events)
        assert any(e.data == "http://127.0.0.1:8888/disallow/" for e in events)
        assert any(e.data == "http://127.0.0.1:8888/sitemap.txt" for e in events)
```
