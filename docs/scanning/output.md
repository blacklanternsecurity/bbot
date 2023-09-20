# Output

By default, BBOT saves its output in TXT, JSON, and CSV formats:
![bbot output](https://github.com/blacklanternsecurity/bbot/assets/20261699/bb3da441-2682-408f-b955-19b268823b82)

Every BBOT scan gets a unique and mildly-entertaining name like **`demonic_jimmy`**. Output for that scan, including scan stats and any web screenshots, etc., are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed. You can change the location of BBOT's output with `--output`, and you can also pick a custom scan name with `--name`.

If you reuse a scan name, it will append to its original output files and leverage the previous.

## Output Modules

Multiple simultaneous output formats are possible because of **output modules**. Output modules are similar to normal modules except they are enabled with `-om`.

### Human

`human` output is tab-delimited, so it's easy to grep:

```bash
# grep out only the DNS_NAMEs
cat ~/.bbot/scans/extreme_johnny/output.txt | grep '[DNS_NAME]' | cut -f2
evilcorp.com
www.evilcorp.com
mail.evilcorp.com
```

### CSV

The `csv` output module produces a CSV like this:

| Event type | Event data              | IP Address | Source Module | Scope Distance | Event Tags                                                                                               |
| ---------- | ----------------------- | ---------- | ------------- | -------------- | -------------------------------------------------------------------------------------------------------- |
| DNS_NAME   | evilcorp.com            | 1.2.3.4    | TARGET        | 0              | a-record,cdn-github,distance-0,domain,in-scope,mx-record,ns-record,resolved,soa-record,target,txt-record |
| DNS_NAME   | www.evilcorp.com        | 2.3.4.5    | certspotter   | 0              | a-record,aaaa-record,cdn-github,cname-record,distance-0,in-scope,resolved,subdomain                      |
| URL        | http://www.evilcorp.com | 2.3.4.5    | httpx         | 0              | a-record,aaaa-record,cdn-github,cname-record,distance-0,in-scope,resolved,subdomain                      |
| DNS_NAME   | admin.evilcorp.com      | 5.6.7.8    | otx           | 0              | a-record,aaaa-record,cloud-azure,cname-record,distance-0,in-scope,resolved,subdomain                     |

### JSON

If you manually enable the `json` output module, it will go to stdout:

```bash
bbot -t evilcorp.com -om json | jq
```

You will then see [events](events.md) like this:

```json
{
  "type": "IP_ADDRESS",
  "id": "IP_ADDRESS:13cd09c2adf0860a582240229cd7ad1dccdb5eb1",
  "data": "1.2.3.4",
  "scope_distance": 1,
  "scan": "SCAN:64c0e076516ae7aa6502fd99489693d0d5ec26cc",
  "timestamp": 1688518967.740472,
  "resolved_hosts": ["1.2.3.4"],
  "source": "DNS_NAME:2da045542abbf86723f22383d04eb453e573723c",
  "tags": ["distance-1", "ipv4", "internal"],
  "module": "A",
  "module_sequence": "A"
}
```

You can filter on the JSON output with `jq`:

```bash
# pull out only the .data attribute of every DNS_NAME
$ jq -r 'select(.type=="DNS_NAME") | .data' ~/.bbot/scans/extreme_johnny/output.ndjson
evilcorp.com
www.evilcorp.com
mail.evilcorp.com
```

### Discord / Slack / Teams

![bbot-discord](https://github.com/blacklanternsecurity/bbot/assets/20261699/6d88045c-8eac-43b6-8de9-c621ecf60c2d)

BBOT supports output via webhooks to `discord`, `slack`, and `teams`. To use them, you must specify a webhook URL either in the config:

```yaml title="~/.bbot/config/bbot.yml"
output_modules:
  discord:
    webhook_url: output_modules.discord.webhook_url=https://discord.com/api/webhooks/1234/deadbeef
```

...or on the command line:
```bash
bbot -t evilcorp.com -om discord -c output_modules.discord.webhook_url=https://discord.com/api/webhooks/1234/deadbeef
```

By default, only `VULNERABILITY` and `FINDING` events are sent, but this can be customized by setting `event_types` in the config like so:

```yaml title="~/.bbot/config/bbot.yml"
output_modules:
  discord:
    event_types:
      - VULNERABILITY
      - FINDING
      - STORAGE_BUCKET
```

...or on the command line:
```bash
bbot -t evilcorp.com -om discord -c output_modules.discord.event_types=["STORAGE_BUCKET","FINDING","VULNERABILITY"]
```

You can also filter on the severity of `VULNERABILITY` events by setting `min_severity`:


```yaml title="~/.bbot/config/bbot.yml"
output_modules:
  discord:
    min_severity: HIGH
```

### HTTP

The `http` output module sends [events](events.md) in JSON format to a desired HTTP endpoint.

```bash
# POST scan results to localhost
bbot -t evilcorp.com -om http -c output_modules.http.url=http://localhost:8000
```

You can customize the HTTP method if needed. Authentication is also supported:

```yaml title="~/.bbot/config/bbot.yml"
output_modules:
  http:
    url: https://localhost:8000
    method: PUT
    # Authorization: Bearer
    bearer: <bearer_token>
    # OR
    username: bob
    password: P@ssw0rd
```

### Asset Inventory

The `asset_inventory` module produces a CSV like this:

| Host               | Provider    | IP(s)   | Status | Open Ports |
| ------------------ | ----------- | ------- | ------ | ---------- |
| evilcorp.com       | cdn-github  | 1.2.3.4 | Active | 80,443     |
| www.evilcorp.com   | cdn-github  | 2.3.4.5 | Active | 22,80,443  |
| admin.evilcorp.com | cloud-azure | 5.6.7.8 | N/A    |            |

### Subdomains

The `subdomains` output module produces simple text file containing only in-scope and resolved subdomains:

```text title="subdomains.txt"
evilcorp.com
www.evilcorp.com
mail.evilcorp.com
portal.evilcorp.com
```

## Neo4j

Neo4j is the funnest (and prettiest) way to view and interact with BBOT data.

![neo4j](https://github.com/blacklanternsecurity/bbot/assets/20261699/0192d548-5c60-42b6-9a1e-32ba7b921cdf)

- You can get Neo4j up and running with a single docker command:

```bash
# start Neo4j in the background with docker
docker run -d -p 7687:7687 -p 7474:7474 -v "$(pwd)/neo4j/:/data/" -e NEO4J_AUTH=neo4j/bbotislife neo4j
```

- After that, run bbot with `-om neo4j`

```bash
bbot -f subdomain-enum -t evilcorp.com -om neo4j
```

- Browse data at [http://localhost:7474](http://localhost:7474)
