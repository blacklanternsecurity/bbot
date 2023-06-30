# Output

By default, BBOT saves its output in TXT, JSON, and CSV formats:
![image](https://github.com/blacklanternsecurity/bbot/assets/20261699/779207f4-1c2f-4f65-a132-794ca8bd2f8a)

You can enable other output modules with `-om`.
~~~bash
# tee to a file
bbot -t evilcorp.com -f subdomain-enum | tee evilcorp.txt

# output JSON to stdout
bbot -t evilcorp.com -f subdomain-enum -om json | jq

# output asset inventory in current directory
bbot -t evilcorp.com -f subdomain-enum -om asset_inventory -o .
~~~
For every scan, BBOT generates a unique and mildly-entertaining name like `demonic_jimmy`. Output for that scan, including scan stats and any gowitness screenshots, etc., are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed. You can change the location of BBOT's output with `--output`, and you can also pick a custom scan name with `--name`.

If you reuse a scan name, it will append to its original output files and leverage the previous.

## Neo4j
Neo4j is the funnest (and prettiest) way to view and interact with BBOT data.

![neo4j](https://user-images.githubusercontent.com/20261699/182398274-729f3c48-c23c-4db0-8c2e-8b403c1bf790.png)

- You can get Neo4j up and running with a single docker command:
~~~bash
docker run -p 7687:7687 -p 7474:7474 -v "$(pwd)/data/:/data/" -e NEO4J_AUTH=neo4j/bbotislife neo4j
~~~
- After that, run bbot with `--output-modules neo4j`
~~~bash
bbot -f subdomain-enum -t evilcorp.com --output-modules neo4j
~~~
- Browse data at [http://localhost:7474](http://localhost:7474)
