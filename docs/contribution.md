# Contribution

We welcome contributions! If you have an idea for a new module, or are a Python developer who wants to get involved, please fork us or come talk to us on [Discord](https://discord.com/invite/PZqkgxu5SA).

## Setting Up a Dev Environment

### Installation (Poetry)

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
black .

# run tests
./bbot/test/run_tests.sh
```

- Finally, commit and push your changes, and create a pull request to the `dev` branch of the main BBOT repo.


## Creating a Module

Writing a module is easy and requires only a basic understanding of Python. It consists of a few steps:

1. Create a new `.py` file in `bbot/modules`
1. At the top of the file, import `BaseModule`
1. Declare a class that inherits from `BaseModule`
   - the class must have the same name as your file (case-insensitive)
1. Define in `watched_events` what type of data your module will consume
1. Define in `produced_events` what type of data your module will produce
1. Define (via `flags`) whether your module is `active` or `passive`, and whether it's `safe` or `aggressive`
1. **Put your main logic in `.handle_event()`**

Here is an example of a simple module that performs whois lookups:

```python title="bbot/modules/whois.py"
from bbot.modules.base import BaseModule

class whois(BaseModule):
    watched_events = ["DNS_NAME"] # watch for DNS_NAME events
    produced_events = ["WHOIS"] # we produce WHOIS events
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for WHOIS data"}
    options = {"api_key": ""} # module config options
    options_desc = {"api_key": "WhoisXMLAPI Key"}
    per_domain_only = True # only run once per domain

    base_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    # one-time setup - runs at the beginning of the scan
    async def setup(self):
        self.api_key = self.config.get("api_key")
        if not self.api_key:
            # soft-fail if no API key is set
            return None, "Must set API key"

    async def handle_event(self, event):
        self.hugesuccess(f"Got {event} (event.data: {event.data})")
        _, domain = self.helpers.split_domain(event.data)
        url = f"{self.base_url}?apiKey={self.api_key}&domainName={domain}&outputFormat=JSON"
        self.hugeinfo(f"Visiting {url}")
        response = await self.helpers.request(url)
        if response is not None:
            await self.emit_event(response.json(), "WHOIS", source=event)
```

After saving the module, you can run it with `-m`:

```bash
# run a scan enabling the module in bbot/modules/mymodule.py
bbot -t evilcorp.com -m whois
```

### `handle_event()` and `emit_event()`

The `handle_event()` method is the most important part of the module. By overriding this method, you control what the module does. During a scan, when an [event](./scanning/events.md) from your `watched_events` is encountered (a `DNS_NAME` in this example), `handle_event()` is automatically called with that event as its argument.

The `emit_event()` method is how modules return data. When you call `emit_event()`, it creates an [event](./scanning/events.md) and outputs it, sending it any modules that are interested in that data type.

### `setup()`

A module's `setup()` method is used for performing one-time setup at the start of the scan, like downloading a wordlist or checking to make sure an API key is valid. It needs to return either:

1. `True` - module setup succeeded
2. `None` - module setup soft-failed (scan will continue but module will be disabled)
3. `False` - module setup hard-failed (scan will abort)

Optionally, it can also return a reason. Here are some examples:

```python
async def setup(self):
    if not self.config.get("api_key"):
        # soft-fail
        return None, "No API key specified"

async def setup(self):
    try:
        wordlist = self.helpers.wordlist("https://raw.githubusercontent.com/user/wordlist.txt")
    except WordlistError as e:
        # hard-fail
        return False, f"Error downloading wordlist: {e}"

async def setup(self):
    self.timeout = self.config.get("timeout", 5)
    # success
    return True
```

### Module Config Options

Each module can have its own set of config options. These live in the `options` and `options_desc` attributes on your class. Both are dictionaries; `options` is for defaults and `options_desc` is for descriptions. Here is a typical example:

```python title="bbot/modules/nmap.py"
class nmap(BaseModule):
    # ...
    options = {
        "top_ports": 100,
        "ports": "",
        "timing": "T4",
        "skip_host_discovery": True,
    }
    options_desc = {
        "top_ports": "Top ports to scan (default 100) (to override, specify 'ports')",
        "ports": "Ports to scan",
        "timing": "-T<0-5>: Set timing template (higher is faster)",
        "skip_host_discovery": "skip host discovery (-Pn)",
    }

    async def setup(self):
        self.ports = self.config.get("ports", "")
        self.timing = self.config.get("timing", "T4")
        self.top_ports = self.config.get("top_ports", 100)
        self.skip_host_discovery = self.config.get("skip_host_discovery", True)
```

Once you've defined these variables, you can pass the options via `-c`:

```bash
bbot -m nmap -c modules.nmap.top_ports=250
```

... or via the config:

```yaml title="~/.config/bbot/bbot.yml"
modules:
  nmap:
    top_ports: 250
```

Inside the module, you access them via `self.config`, e.g.:

```python
self.config.get("top_ports")
```

### Module Dependencies

BBOT automates module dependencies with **Ansible**. If your module relies on a third-party binary, OS package, or python library, you can specify them in the `deps_*` attributes of your module.

```python
class MyModule(BaseModule):
    ...
    deps_apt = ["chromium-browser"]
    deps_ansible = [
        {
            "name": "install dev tools",
            "package": {"name": ["gcc", "git", "make"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "#{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns",
            "command": {"chdir": "#{BBOT_TEMP}/massdns", "cmd": "make", "creates": "#{BBOT_TEMP}/massdns/bin/massdns"},
        },
        {
            "name": "Install massdns",
            "copy": {"src": "#{BBOT_TEMP}/massdns/bin/massdns", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
```
