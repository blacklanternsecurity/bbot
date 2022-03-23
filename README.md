![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BBOT
OSINT automation for hackers.

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![License](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Installation
~~~bash
git clone git@github.com:blacklanternsecurity/bbot.git && cd bbot
poetry install
~~~

## Example scan
~~~bash
poetry run bbot -m naabu httpx nuclei -t evilcorp.com 1.2.3.4/28 4.3.2.1
~~~

## Run tests
~~~
$ poetry run pytest
~~~

## Usage
~~~bash
$ bbot --help
usage: bbot [-h] [-v] [-t TARGETS [TARGETS ...]] [-m {nuclei,nmap,naabu,httpx,dnsx} [{nuclei,nmap,naabu,httpx,dnsx} ...]] [configuration ...]

Bighuge BLS OSINT Tool

positional arguments:
  configuration         additional configuration options in key=value format

options:
  -h, --help            show this help message and exit
  -v, --verbose, --debug
                        Be more verbose
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        Scan target
  -m {nuclei,nmap,naabu,httpx,dnsx} [{nuclei,nmap,naabu,httpx,dnsx} ...], --modules {nuclei,nmap,naabu,httpx,dnsx} [{nuclei,nmap,naabu,httpx,dnsx} ...]
                        Modules
~~~

## Writing modules
From within a module, you can easily access scan information and helper functions:
~~~python
# Access scan target:
if event in self.scan.target:
    self.info(f"Event {event} is part of target!")

# Use a helper function
if not self.helpers.is_domain(event.data):
    self.warning(f"Event {event} is not a domain.")

# Make a web request
response = self.helpers.request("https://evilcorp.com")
~~~