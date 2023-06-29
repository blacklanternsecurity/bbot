## Installation

BBOT offers multiple methods of installation, including **pipx** and **Docker**. If you plan to dev on BBOT, please see [Installation (Poetry)](./contribution).

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

## Example Scans

---

<!-- BBOT EXAMPLE COMMANDS -->

### Subdomains
Enable all modules with the `subdomain-enum` flag
```bash
bbot -t evilcorp.com -f subdomain-enum
```

### Subdomains (passive only)
Require modules to have the `passive` flag
```bash
bbot -t evilcorp.com -f subdomain-enum -rf passive
```

### Subdomains + port scan + web screenshots
Port-scan every subdomain, screenshot every webpage, output to current directory
```bash
bbot -t evilcorp.com -f subdomain-enum -m nmap gowitness -n my_scan -o .
```

### Subdomains + basic web scan
A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules
```bash
bbot -t evilcorp.com -f subdomain-enum web-basic
```

### Web Spider
Use the web spider to crawl for emails, secrets, etc.
```bash
bbot -t www.evilcorp.com -m httpx badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2
```

### Subdomains + emails + cloud + port scan + basic web + web screenshots + nuclei
Everything everywhere all at once
```bash
bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly
```

### List modules

```bash
bbot -l
```

### List flags

```bash
bbot -lf
```

<!-- END BBOT EXAMPLE COMMANDS -->
