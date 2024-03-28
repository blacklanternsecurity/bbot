# Getting Started

<video controls="" autoplay="" name="media"><source src="https://github-production-user-asset-6210df.s3.amazonaws.com/20261699/245941416-ebf2a81e-7530-4a9e-922d-4e62eb949f35.mp4" type="video/mp4"></video>

_A BBOT scan in real-time - visualization with [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)_

## Installation

!!! info "Supported Platforms"

    Only **Linux** is supported at this time. **Windows** and **macOS** are *not* supported. If you use one of these platforms, consider using [Docker](#Docker).

BBOT offers multiple methods of installation, including **pipx** and **Docker**. If you plan to dev on BBOT, see [Installation (Poetry)](./contribution/#installation-poetry).

### [Python (pip / pipx)](https://pypi.org/project/bbot/)


???+ note inline end

    `pipx` installs BBOT inside its own virtual environment.

```bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot

# execute bbot command
bbot --help
```

### [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot)

Docker images are provided, along with helper script `bbot-docker.sh` to persist your scan data.

```bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# helper script
git clone https://github.com/blacklanternsecurity/bbot && cd bbot
./bbot-docker.sh --help
```

## Example Commands

Below are some examples of common scans.

<!-- BBOT EXAMPLE COMMANDS -->
**Subdomains:**

```bash
# Perform a full subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -p subdomain-enum
```

**Subdomains (passive only):**

```bash
# Perform a passive-only subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -p subdomain-enum -rf passive
```

**Subdomains + port scan + web screenshots:**

```bash
# Port-scan every subdomain, screenshot every webpage, output to current directory
bbot -t evilcorp.com -p subdomain-enum -m nmap gowitness -n my_scan -o .
```

**Subdomains + basic web scan:**

```bash
# A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules
bbot -t evilcorp.com -p subdomain-enum web-basic
```

**Web spider:**

```bash
# Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.
bbot -t www.evilcorp.com -p spider -c web_spider_distance=2 web_spider_depth=2
```

**Everything everywhere all at once:**

```bash
# Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei
bbot -t evilcorp.com -p kitchen-sink
```
<!-- END BBOT EXAMPLE COMMANDS -->

## API Keys

BBOT works just fine without API keys. However, there are certain modules that need them to function. If you have API keys and want to make use of these modules, you can place them either in your preset:

```yaml title="my_preset.yml"
description: My custom subdomain enum preset

include:
  - subdomain-enum
  - cloud-enum

config:
  modules:
    shodan_dns:
      api_key: deadbeef
    virustotal:
      api_key: cafebabe
```

...in BBOT's global YAML config (`~/.config/bbot/bbot.yml`):

Note: this will ensure the API keys are used in all scans, regardless of preset.

```yaml title="~/.config/bbot/secrets.yml"
modules:
  shodan_dns:
    api_key: deadbeef
  virustotal:
    api_key: cafebabe
```

...or directly on the command-line:

```bash
# specify API key with -c
bbot -t evilcorp.com -f subdomain-enum -c modules.shodan_dns.api_key=deadbeef modules.virustotal.api_key=cafebabe
```

For more information, see [Configuration](./scanning/configuration.md). For a full list of modules, including which ones require API keys, see [List of Modules](./modules/list_of_modules.md).

[Next Up: Scanning -->](./scanning/index.md){ .md-button .md-button--primary }
