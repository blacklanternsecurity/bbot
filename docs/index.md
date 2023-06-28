## Installation

BBOT offers multiple methods of installation, including **pipx** and **Docker**. If you want to dev on BBOT, please see [Installation (Poetry)](./contribution).

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
BBOT provides docker images, along with helper script `bbot-docker.sh` to persist your BBOT scan data.
~~~bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# helper script
git clone https://github.com/blacklanternsecurity/bbot && cd bbot
./bbot-docker.sh --help
~~~

## First Scan

Execute a subdomain enumeration against `evilcorp.com`:
~~~bash
bbot -t evilcorp.com -f subdomain-enum
~~~

## Example Scans