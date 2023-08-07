# Nuclei

## Overview

BBOT's interface with the open-source vulnerability scanner [Nuclei](https://github.com/projectdiscovery/nuclei) by Project Discovery. This is one of the ways BBOT makes it possible to go from a domain name or IP all the way to confirmed vulnerabilities, in one scan. 

* The BBOT Nuclei module ingests **[URL]** events and emits events of type **[VULNERABILITY]** or **[FINDING]**
* Vulnerabilities will inherit their severity from the Nuclei templates​
* Nuclei templates of severity INFO will be emitted as **[FINDINGS]**​

## Default Behavior

* By default, it will scan *only directory URLs*, but it will scan with ALL templates (**BE CAREFUL!**)
* Because it's so aggressive, its considered a **deadly** module. This means you need to use the flag **--allow-deadly** to turn it on


