# Comparison to Other Tools

BBOT isn't exclusively a subdomain enumeration tool. However since there's so many of them, subdomain enumeration tools are the easiest class of tool to compare it to.

Thanks to BBOT's recursive nature (and `massdns`' fancy subdomain mutations), it typically finds about 20-25% more than other tools such as `Amass` or `theHarvester`.

This holds true even for larger targets like `boeing.com` (1000+ subdomains):

![subdomain-stats-boeing](https://github.com/blacklanternsecurity/bbot/assets/20261699/de0154c1-476e-4337-9599-45a1c5e0e78b)
