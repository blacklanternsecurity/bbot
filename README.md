![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BEE·bot
### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.7+-blue)](https://www.python.org) [![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/workflows/tests/badge.svg)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Installation
~~~bash
git clone git@github.com:blacklanternsecurity/bbot.git && cd bbot
poetry install
~~~

## Example scan
~~~bash
poetry run bbot -m naabu httpx nuclei -t evilcorp.com 1.2.3.4/28 4.3.2.1
~~~

## Tests
~~~bash
# run tests
poetry run bbot/test/run_tests.sh

# format with black
black .
~~~

## Adding a dependency
~~~
1. poetry add <package>
2. poetry export --without-hashes > requirements.txt
3. poetry export --dev --without-hashes > requirements-dev.txt
~~~

## Usage
~~~bash
$ bbot --help
usage: bbot [-h] [-t TARGETS [TARGETS ...]] [-m MODULES [MODULES ...]] [-om MODULES [MODULES ...]] [-c [CONFIGURATION ...]] [-v] [-d] [--current-config]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        Scan target
  -m MODULES [MODULES ...], --modules MODULES [MODULES ...]
                        Modules (specify keyword "all" to enable all modules). Choices:
                        ffuf,sslcert,aspnet_viewstate,nuclei,telerik,naabu,httpx,wayback,dnsx,dnsresolve,sublist3r,dnsdumpster
  -om MODULES [MODULES ...], --output-modules MODULES [MODULES ...]
                        Output module(s). Choices: json,neo4j,csv,human
  -c [CONFIGURATION ...], --configuration [CONFIGURATION ...]
                        additional configuration options in key=value format
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  --current-config      Show current config in YAML format
~~~

## Generate config
To generate a full config file from the current config (including module defaults, etc.), run the following command:
~~~
$ bbot --current-config > bbot.conf
~~~

## Writing modules
Modules have easy access to scan information and helper functions:
~~~python
# Access scan target:
if event in self.scan.target:
    self.info(f"{event} is part of target!")

# Use a helper function
if not self.helpers.is_domain(event.data):
    self.warning(f"{event} is not a domain.")

# Access module config
if not self.config.api_key:
    self.error(f"No API key specified for module.{self.name}!")

# Download a file
filename = self.helpers.download(self.config.get("wordlist"), cache_hrs=720)

# Make a web request
response = self.helpers.request("https://evilcorp.com")

# Make a DNS query
mx_records = self.helpers.resolve("evilcorp.com", type="mx")

# Reverse resolve IP
ptrs = self.helpers.resolve("8.8.8.8")

# Execute a shell command
process = self.helpers.run(["ls", "-lah"])
log.info(process.stdout)

# Use the shared thread pool
# limit threads by setting self.max_threads
futures = {}
for url in urls:
    future = self.submit_task(self.helpers.request, url)
    futures[future] = url

for future in self.helpers.as_completed(futures):
    url = futures[future]
    response = future.result()
    if getattr(response, "status_code", 0) == 200:
        log.success(f"Found URL: {url}")

# Access the global word cloud
# The word cloud contains commonly-encountered words from the scan
# These words come from dns names, etc., and you can use them for 
# smart brute-forcing of subdomains, vhosts, storage buckets, etc.
self.helpers.word_cloud
# {"www": 1, black": 3, "lantern": 1, "security": 1, ...}
self.helpers.word_cloud.modifiers()
# {"1", "2", "3", "dev", "api", "test", "qa", ...}
self.helpers.word_cloud.mutations("word")
"""
[
    ("word", "dev"),
    ("dev", "word"),
    ("word", "api"),
    ("api", "word"),
    ("word", "1"),
    ("1", "word")
]
"""
~~~