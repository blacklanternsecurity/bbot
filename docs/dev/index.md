# BBOT Developer Reference

BBOT exposes a Python API that allows you to create, start, and stop scans.

Documented in this section are commonly-used classes and functions within BBOT, along with usage examples.

## Adding BBOT to Your Python Project

If you are using Poetry, you can add BBOT to your python environment like this:

```bash
# stable
poetry add bbot

# bleeding-edge (dev branch)
poetry add bbot --allow-prereleases
```

## Running a BBOT Scan from Python

#### Synchronous
```python
from bbot.scanner import Scanner

if __name__ == "__main__":
    scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
    for event in scan.start():
        print(event)
```

#### Asynchronous
```python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
    async for event in scan.async_start():
        print(event.json())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

For a full listing of `Scanner` attributes and functions, see the [`Scanner` Code Reference](./scanner.md).

#### Multiple Targets

You can specify any number of targets:

```python
# create a scan against multiple targets
scan = Scanner(
    "evilcorp.com",
    "evilcorp.org",
    "evilcorp.ce",
    "4.3.2.1",
    "1.2.3.4/24",
    presets=["subdomain-enum"]
)

# this is the same as:
targets = ["evilcorp.com", "evilcorp.org", "evilcorp.ce", "4.3.2.1", "1.2.3.4/24"]
scan = Scanner(*targets, presets=["subdomain-enum"])
```

For more details, including which types of targets are valid, see [Targets](../scanning/index.md#targets)

#### Other Custom Options

In many cases, using a [Preset](../scanning/presets.md) like `subdomain-enum` is sufficient. However, the `Scanner` is flexible and accepts many other arguments that can override the default functionality. You can specify [`flags`](../index.md#flags), [`modules`](../index.md#modules), [`output_modules`](../output.md), a [`whitelist` or `blacklist`](../scanning/index.md#whitelists-and-blacklists), and custom [`config` options](../scanning/configuration.md):

```python
# create a scan against multiple targets
scan = Scanner(
    # targets
    "evilcorp.com",
    "4.3.2.1",
    # enable these presets
    presets=["subdomain-enum"],
    # whitelist these hosts
    whitelist=["evilcorp.com", "evilcorp.org"],
    # blacklist these hosts
    blacklist=["prod.evilcorp.com"],
    # also enable these individual modules
    modules=["nuclei", "ipstack"],
    # exclude modules with these flags
    exclude_flags=["slow"],
    # custom config options
    config={
        "modules": {
            "nuclei": {
                "tags": "apache,nginx"
            }
        }
    }
)
```

For a list of all the possible scan options, see the [`Presets` Code Reference](./presets.md)
