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
1. **Override `.handle_event()`** (see [`handle_event()` and `emit_event()`](#handle_event-and-emit_event))

Here is a simple example of a working module (`bbot/modules/mymodule.py`):

```python
from bbot.modules.base import BaseModule

class MyModule(BaseModule):
    """
    Resolve DNS_NAMEs to IPs
    """
    watched_events = ["DNS_NAME"]
    produced_events = ["IP_ADDRESS"]
    flags = ["passive", "safe"]

    async def handle_event(self, event):
        self.hugeinfo(f"GOT EVENT: {event}")
        for ip in await self.helpers.resolve(event.data):
            self.hugesuccess(f"EMITTING IP_ADDRESS: {ip}")
            await self.emit_event(ip, "IP_ADDRESS", source=event)
```

After saving the module, you can run it simply by specifying it with `-m`:

```bash
# run a scan enabling the module in bbot/modules/mymodule.py
bbot -t evilcorp.com -m mymodule
```

This will produce the output:

```text
[SUCC] Starting scan satanic_linda
[SCAN]                  satanic_linda (SCAN:2e9ec8b6f06875bcf7980eea4c150754b53a6049)  TARGET  (distance-0)
[INFO] mymodule: GOT EVENT: DNS_NAME("dns.google", module=TARGET, tags={'aaaa-record', 'ns-record', 'target', 'domain', 'a-record', 'resolved', 'txt-record', 'soa-record', 'distance-0', 'in-scope'})
[DNS_NAME]              dns.google  TARGET  (a-record, aaaa-record, distance-0, domain, in-scope, ns-record, resolved, soa-record, target, txt-record)
[INFO] Finishing scan
```

But something's wrong! We're emitting `IP_ADDRESS` [events](./scanning/events.md), but they're not showing up in the output. This is because by default, BBOT only shows in-scope [events](./scanning/events.md). To see them, we need to increase the report distance:

```bash
# run the module again but with a higher report distance
# this lets us see out-of-scope events (up to distance 1)
bbot -t evilcorp.com -m mymodule -c scope_report_distance=1
```

Now, with the `report_distance=1`:

```text
[SUCC] Starting scan suspicious_dobby
[SCAN]                  suspicious_dobby (SCAN:e9d28f64527da53eaffc16f46f5deb20103bc78b)    TARGET  (distance-0)
[INFO] mymodule: GOT EVENT: DNS_NAME("dns.google", module=TARGET, tags={'soa-record', 'aaaa-record', 'ns-record', 'txt-record', 'distance-0', 'in-scope', 'resolved', 'domain', 'a-record', 'target'})
[DNS_NAME]              dns.google  TARGET  (a-record, aaaa-record, distance-0, domain, in-scope, ns-record, resolved, soa-record, target, txt-record)
[IP_ADDRESS]            8.8.4.4 mymodule   (distance-1, ipv4, ptr-record, resolved)
[IP_ADDRESS]            2001:4860:4860::8888    mymodule    (distance-1, ipv6, ptr-record, resolved)
[IP_ADDRESS]            8.8.8.8 mymodule   (distance-1, ipv4, ptr-record, resolved)
[IP_ADDRESS]            2001:4860:4860::8844    mymodule    (distance-1, ipv6, ptr-record, resolved)
[DNS_NAME]              ns3.zdns.google NS  (a-record, aaaa-record, distance-1, resolved, subdomain)
[DNS_NAME]              ns1.zdns.google NS  (a-record, aaaa-record, distance-1, resolved, subdomain)
[DNS_NAME]              ns4.zdns.google NS  (a-record, aaaa-record, distance-1, resolved, subdomain)
[DNS_NAME]              ns2.zdns.google NS  (a-record, aaaa-record, distance-1, resolved, subdomain)
[DNS_NAME]              xkcd.com    TXT (a-record, aaaa-record, distance-1, domain, mx-record, ns-record, resolved, soa-record, txt-record)
[INFO] Finishing scan
```

### `handle_event()` and `emit_event()`

The `handle_event()` method is the most important part of the module. By overriding this method, you control what the module does. During a scan, when an [event](./scanning/events.md) from your `watched_events` is encountered (a `DNS_NAME` in this example), `handle_event()` is automatically called with that event.

The `emit_event()` method is how modules return data. When you call `emit_event()`, it creates an [event](./scanning/events.md) and prints it to the console. It also distributes it any modules that are interested in that data type.

### Module Dependencies

BBOT automates module dependencies with **Ansible**. If your module relies on a third-party binary, OS package, or python library, you can specify them in the `deps_*` attributes of your module.

```python
class MyModule(BaseModule):
    ...
    deps_pip = ["beautifulsoup4"]
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
