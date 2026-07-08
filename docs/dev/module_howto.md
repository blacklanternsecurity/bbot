# How to Write a BBOT Module

Here we'll go over a basic example of writing a custom BBOT module.

## Create the python file

1. Create a new `.py` file in `bbot/modules` (or in a [custom module directory](#load-modules-from-custom-locations))
1. At the top of the file, import `BaseModule`
1. Declare a class that inherits from `BaseModule`
   - the class must have the same name as your file (case-insensitive)
1. Define in `watched_events` what type of data your module will consume
1. Define in `produced_events` what type of data your module will produce
1. Define (via `flags`) whether your module is `active` or `passive`, and whether it's `safe`, `loud`, or `invasive`
1. **Put your main logic in `.handle_event()`**

Here is an example of a simple module that performs whois lookups:

```python title="bbot/modules/whois.py"
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field

class whois(BaseModule):
    watched_events = ["DNS_NAME"] # watch for DNS_NAME events
    produced_events = ["DNS_NAME"] # we produce DNS_NAME events
    flags = ["passive", "safe"]
    meta = {"description": "Query WhoisXMLAPI for related domains", "created_date": "2024-01-01", "author": "@you"}

    class Config(BaseModuleConfig):
        api_key: str = Field("", description="WhoisXMLAPI Key", sensitive=True, mandatory=True)

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
            for related_domain in response.json().get("domains", []):
                await self.emit_event(related_domain, "DNS_NAME", parent=event)
```

## Test your new module

After saving the module, you can run it with `-m`:

```bash
# run a scan enabling the module in bbot/modules/mymodule.py
bbot -t evilcorp.com -m whois
```

### Debugging Your Module

BBOT has a variety of colorful logging functions like `self.hugesuccess()` that can be useful for debugging.

**BBOT log levels**:

- `critical`: bright red
- `hugesuccess`: bright green
- `hugewarning`: bright orange
- `hugeinfo`: bright blue
- `error`: red
- `warning`: orange
- `info`: blue
- `verbose`: grey (must enable `-v` to see)
- `debug`: grey (must enable `-d` to see)


For details on how tests are written, see [Unit Tests](./tests.md).

## `handle_event()` and `emit_event()`

The `handle_event()` method is the most important part of the module. By overriding this method, you control what the module does. During a scan, when an [event](../scanning/events.md) from your `watched_events` is encountered (a `DNS_NAME` in this example), `handle_event()` is automatically called with that event as its argument.

The `emit_event()` method is how modules return data. When you call `emit_event()`, it creates an [event](../scanning/events.md) and outputs it, sending it any modules that are interested in that data type.

## `setup_deps()` and `setup()`

`setup_deps()` and `setup()` are used for performing one-time setup at the start of the scan.

`setup_deps()` is reserved for downloading or installing any dependencies not covered by Ansible, i.e. AI models or wordlists. Any other one-time setup tasks can be put into `setup()`.

These methods must return either:

1. `True` - module setup succeeded
2. `None` - module setup soft-failed (scan will continue but module will be disabled)
3. `False` - module setup hard-failed (scan will abort)

Optionally, it can also return a reason. Here are some examples:

```python
async def setup(self):
    if not self.config.get("api_key"):
        # soft-fail
        return None, "No API key specified"
    return True

async def setup_deps(self):
    self.wordlist = self.helpers.wordlist("https://raw.githubusercontent.com/user/wordlist.txt")
    return True

async def setup(self):
    self.timeout = self.config.get("timeout", 5)
    if self.timeout <= 0:
        return False, "Timeout must be greater than or equal to 0"
    # success
    return True
```

## Module Config Options

Each module can have its own set of config options. These are defined as a `Config` inner class that inherits from `BaseModuleConfig`, using pydantic `Field` for defaults and descriptions. Here is a typical example:

```python title="bbot/modules/portscan.py"
from bbot.core.config.models import BaseModuleConfig, Field

class portscan(BaseModule):
    # ...
    class Config(BaseModuleConfig):
        top_ports: int = Field(100, description="Top ports to scan (default 100) (to override, specify 'ports')")
        ports: str = Field("", description="Ports to scan")
        rate: int = Field(300, description="Rate in packets per second")
        wait: int = Field(5, description="Seconds to wait for replies after scan is complete")

    async def setup(self):
        self.ports = self.config.get("ports", "")
        self.rate = self.config.get("rate", 300)
        self.top_ports = self.config.get("top_ports", 100)
        return True
```

For API keys and other secrets, use `sensitive=True` (redacted in logs) and `mandatory=True` (module soft-fails if not set):

```python
class Config(BaseModuleConfig):
    api_key: str = Field("", description="API Key", sensitive=True, mandatory=True)
```

Once you've defined these fields, you can pass the options via `-c`:

```bash
bbot -m portscan -c modules.portscan.top_ports=250
```

... or via the config:

```yaml title="~/.config/bbot/bbot.yml"
modules:
  portscan:
    top_ports: 250
```

Inside the module, you access them via `self.config`, e.g.:

```python
self.config.get("top_ports")
```

## Module Dependencies

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

## Load Modules from Custom Locations

If you have a custom module and you want to use it with BBOT, you can add its parent folder to `module_dirs`. This saves you from having to copy it into the BBOT install location. To add a custom module directory, add it to `module_dirs` in your preset:

```yaml title="my_preset.yml"
# load BBOT modules from these additional paths
module_dirs:
  - /home/user/my_modules
```
