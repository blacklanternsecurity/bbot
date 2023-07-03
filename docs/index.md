# Getting Started

## Installation

BBOT offers multiple methods of installation, including **pipx** and **Docker**. If you plan to dev on BBOT, see [Installation (Poetry)](https://www.blacklanternsecurity.com/bbot/contribution#installation-poetry).

### [Python (pip / pipx)](https://pypi.org/project/bbot/)
Note: `pipx` installs BBOT inside its own virtual environment.
~~~bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pre bbot

# execute bbot command
bbot --help
~~~

### [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot)
Docker images are provided, along with helper script `bbot-docker.sh` to persist your scan data.
~~~bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# helper script
git clone https://github.com/blacklanternsecurity/bbot && cd bbot
./bbot-docker.sh --help
~~~

## Examples

Below are some common scan examples.

<!-- BBOT EXAMPLE COMMANDS -->
**Subdomains:**
```bash
# Perform a full subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -f subdomain-enum
```

**Subdomains (passive only):**
```bash
# Perform a passive-only subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -f subdomain-enum -rf passive
```

**Subdomains + port scan + web screenshots:**
```bash
# Port-scan every subdomain, screenshot every webpage, output to current directory
bbot -t evilcorp.com -f subdomain-enum -m nmap gowitness -n my_scan -o .
```

**Subdomains + basic web scan:**
```bash
# A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules
bbot -t evilcorp.com -f subdomain-enum web-basic
```

**Web spider:**
```bash
# Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.
bbot -t www.evilcorp.com -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2
```

**Everything everywhere all at once:**
```bash
# Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei
bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly
```
<!-- END BBOT EXAMPLE COMMANDS -->

## Next: [Scanning](./scanning)
