![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BBOT

## Installation
~~~bash
git clone git@github.com:blacklanternsecurity/bbot.git && cd bbot
poetry install
~~~

## Example
~~~bash
poetry run bbot -m naabu httpx nuclei -t evilcorp.com 1.2.3.4/28 4.3.2.1
~~~

## Usage
~~~bash
bbot --help
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