# How it Works

## BBOT's Recursive Philosophy

The most important thing to understand about BBOT is that its philosophy is fundamentally different from other tools. At Black Lantern Security, we believe that the only correct way to do discovery is through ***Recursion***.

The vast majority of offensive tools are not recursive. Some may leverage recursion in a small isolated way, such as a dirbuster that finds subdirectories of subdirectories. What makes BBOT special is its 100+ custom modules, which have been carefully designed to work together in a ***truly recursive*** system. 

Each module ***consumes*** a certain type of data, uses it to discover something new, and ***produces*** another type, which it distributes to all the other modules. This happens again and again -- thousands of times during a scan -- spidering outwards in a recursive web of discovery.

The interactive graph below shows the relationships between modules and the data types they consume and produce.

<!-- BBOT CHORD GRAPH -->
<div id="vis"></div>
<script type="text/javascript">
  window.addEventListener(
    'load',
    function() {
      vegaEmbed(
        '#vis',
        '/bbot/data/chord_graph/vega.json',
        {renderer: 'svg'}
      );
    }
  );
</script>
<!-- END BBOT CHORD GRAPH -->

## How BBOT Modules Work Together

BBOT inherits its recursive philosophy from [Spiderfoot](https://github.com/smicallef/spiderfoot). This enables its modules to work together in an efficient and very effective way.

For example, the `portscan` module consumes `DNS_NAME`, and produces `OPEN_TCP_PORT`. The `sslcert` module consumes `OPEN_TCP_PORT` and produces `DNS_NAME`. You can see how even these two modules, when enabled together, will feed each other recursively.

![bbot-modules-work-together](https://github.com/blacklanternsecurity/bbot/assets/20261699/a4c4965b-428b-40aa-afa2-a0f371dc2cb7)

Every BBOT module is designed to interwork with all the others in this recursive system. Because of this, enabling even one module has the potential to increase your results exponentially. This is exactly how BBOT is able to outperform other tools.

## Example: Subdomain Enumeration

Let's take subdomain enumeration as an example, since this is a task most of us are pretty familiar with.

Check out this subdomain enum workflow from [Trickest](https://trickest.com/):

![trickest-subdomain-workflow](https://github.com/blacklanternsecurity/bbot/assets/20261699/4ea0c60c-35f7-4ead-943a-a7f524af474b)

This workflow stitches together a bunch of different recon tools. It starts at the left and works forward:

1. Passive enumeration (Scraping/APIs)
2. DNS Brute Force
3. DNS Brute Force (Permutations)
4. Port Scan
5. HTTP

If you ever had a bash script that did something similar to this, Trickest lets you to automate it in a visual, drag-and-drop kind of way. Pretty neat!

But there's a flaw with this approach. The flaw isn't specific to Trickest, and it's not easy to spot at first. But it causes quite a few subdomains to be missed. Let's run BBOT and compare its output to Trickest.

```bash
bbot -t ebay.com -p subdomain-enum
```

## Recursive vs. Non-Recursive - Real-World Comparison

<insert subdomain comparison>

What happened here? How is BBOT -- a single tool -- able to find more subdomains than this entire Trickest workflow? The two have more or less the same features -- passive enumeration, DNS brute force, subdomain permutations, port scanner, and web client. Individually, these features are pretty comparable.

The difference is in the underlying philosophy. Trickest (and the tools it's leveraging) use a one-time, one-way enumeration. This approach produces results that are shallow and incomplete. There's also a fair amount of wastefulness in running five separate tools which under the hood are calling the same APIs multiple times.

Alternatively, BBOT runs in a perpetual cycle, feeding each result back into itself to continually fuel its discovery. It finds subdomains of subdomains of subdomains, permutations of permutations of permutations. It portscans hosts, visits their websites, extracts new subdomains, generates permutations of them, portscans those permutations, visits their websites, and so on infinitely until there is nothing left to be discovered:

![recursion](https://github.com/blacklanternsecurity/bbot/assets/20261699/7b2edfca-2692-463b-939b-ab9d52d2fe00)

This recursive philosophy is what makes BBOT so powerful, and it's what enables it to find far-out goodies that are ten or even twenty hops away from the starting point. Below is a real subdomain, `secureaccess-dev.corp.ebay.com`, which was discovered by BBOT, but is mysteriously missing from Trickest's output:

```json
{
  "type": "DNS_NAME",
  "data": "secureaccess-dev.corp.ebay.com",
  "discovery_path": [
    "Scan heightened_sean seeded with DNS_NAME: ebay.com",
    "rapiddns searched rapiddns API for \"ebay.com\" and found DNS_NAME: mxphxpool2044.ebay.com",
    "A record for mxphxpool2044.ebay.com contains IP_ADDRESS: 66.211.185.207",
    "ipneighbor produced IP_ADDRESS: 66.211.185.204",
    "PTR record for 66.211.185.204 contains DNS_NAME: mxphxpool2041.ebay.com",
    "dnsbrute_mutations found a mutated subdomain of \"listings.in.paradise.qa.ebay.com\" on its 1st run: DNS_NAME: crafts.listings.in.paradise.qa.ebay.com",
    "dnsbrute_mutations found a mutated subdomain of \"corp.ebay.com\" on its 4th run: DNS_NAME: secureaccess-dev.corp.ebay.com",
    "speculated OPEN_TCP_PORT: secureaccess-dev.corp.ebay.com:443",
    "httpx visited secureaccess-dev.corp.ebay.com:443 and got status code 302 at https://secureaccess-dev.corp.ebay.com/",
    "HTTP_RESPONSE was 0B with unspecified content type",
    "excavate's hostname extractor found DNS_NAME: secureaccess-dev.corp.ebay.com from HTTP response headers using regex derived from target domain"
  ]
}
```
