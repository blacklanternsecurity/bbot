# Events

An Event is a piece of data discovered by BBOT. Examples include `IP_ADDRESS`, `DNS_NAME`, `EMAIL_ADDRESS`, `URL`, etc. When you run a BBOT scan, events are constantly being exchanged between modules. They are also output to the console:

```text
[DNS_NAME]      www.evilcorp.com    sslcert         (distance-0, in-scope, resolved, subdomain, a-record)
 ^^^^^^^^       ^^^^^^^^^^^^^^^^    ^^^^^^^          ^^^^^^^^^^
event type      event data          source module    tags
```

In addition to the obvious data (e.g. `www.evilcorp.com`), an event also contains other useful information such as:

- a `.timestamp` of when the data was discovered
- the `.module` that discovered it
- the `.source` event that led to its discovery
- its `.scope_distance` (how many hops it is from the main scope, 0 == in-scope)
- a list of `.tags` that describe the data (`mx-record`, `http-title`, etc.)

These attributes allow us to construct a visual graph of events (e.g. in [Neo4j](../output#neo4j)) and query/filter/grep them more easily. Here is what a typical event looks like in JSON format:

```json
{
  "type": "URL",
  "id": "URL:017ec8e5dc158c0fd46f07169f8577fb4b45e89a",
  "data": "http://www.blacklanternsecurity.com/",
  "web_spider_distance": 0,
  "scope_distance": 0,
  "scan": "SCAN:4d786912dbc97be199da13074699c318e2067a7f",
  "timestamp": 1688526222.723366,
  "resolved_hosts": ["185.199.108.153"],
  "source": "OPEN_TCP_PORT:cf7e6a937b161217eaed99f0c566eae045d094c7",
  "tags": [
    "in-scope",
    "distance-0",
    "dir",
    "ip-185-199-108-153",
    "status-301",
    "http-title-301-moved-permanently"
  ],
  "module": "httpx",
  "module_sequence": "httpx"
}
```

Below is a full list of event types along with which modules produce/consume them.

## List of Event Types

<!-- BBOT EVENTS -->
<!-- END BBOT EVENTS -->
