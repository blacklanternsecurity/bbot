# Comparison to Other Tools

BBOT isn't exclusively a subdomain enumeration tool. However since there's so many of them, subdomain enumeration tools are the easiest class of tool to compare it to.

Thanks to BBOT's recursive nature (and `massdns`' fancy subdomain mutations), it typically finds about 20-25% more than other tools such as `Amass` or `theHarvester`.

This holds true even for larger targets like `boeing.com` (1000+ subdomains):

![subdomain-stats-boeing](https://github.com/blacklanternsecurity/bbot/assets/20261699/1c262bbe-2e8c-4c69-bdd2-1e2553d47746)
