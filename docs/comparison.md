# Comparison to Other Tools

BBOT does a lot more than just subdomain enumeration. However, subdomain enumeration is arguably the most important part of OSINT, and since there's so many subdomain enumeration tools out there, they're the easiest class of tool to compare it to.

Thanks to BBOT's recursive nature (and its `massdns` module with its NLP-powered subdomain mutations), it typically finds about 20-25% more than other tools such as `Amass` or `theHarvester`. This holds true even for larger targets like `delta.com` (1000+ subdomains):

### Subdomains Found

![subdomains](https://github.com/blacklanternsecurity/bbot/assets/20261699/0d7eb982-e68a-4a33-b33c-7c8ba8c7d6ad)

### Runtimes (Lower is Better)

![runtimes](https://github.com/blacklanternsecurity/bbot/assets/20261699/66cafb5f-045b-4d88-9ffa-7542b3dada4f)

For a detailed analysis of this data, please see [Subdomain Enumeration Tool Face-Off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off-4e5)

### Ebay.com (larger domain)

![subdomain-stats-ebay](https://github.com/blacklanternsecurity/bbot/assets/20261699/53e07e9f-50b6-4b70-9e83-297dbfbcb436)

_Note that in this benchmark, Spiderfoot crashed after ~20 minutes due to excessive memory usage. Amass never finished and had to be cancelled after 24h. All other tools finished successfully._
