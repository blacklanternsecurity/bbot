# Nuclei

## Overview

BBOT's interface with the open-source vulnerability scanner [Nuclei](https://github.com/projectdiscovery/nuclei) by Project Discovery. This is one of the ways BBOT makes it possible to go from a domain name or IP all the way to confirmed vulnerabilities, in one scan. 

![Nuclei Killchain](https://github.com/blacklanternsecurity/bbot/assets/24899338/7174c4ba-4a6e-4596-bb89-5a0c5f5abe74)


* The BBOT Nuclei module ingests **[URL]** events and emits events of type **[VULNERABILITY]** or **[FINDING]**
* Vulnerabilities will inherit their severity from the Nuclei templates​
* Nuclei templates of severity INFO will be emitted as **[FINDINGS]**

## Default Behavior

* By default, it will scan *only directory URLs*, but it will scan with ALL templates (**BE CAREFUL!**)
* Because it's so aggressive, its considered a **deadly** module. This means you need to use the flag **--allow-deadly** to turn it on.

## Configuration and Options

The Nuclei module has many configuration options:

| Option         | Description                                                              | Default |
|----------------|--------------------------------------------------------------------------|---------|
| version        | What version of Nuclei to use                                            | 2.9.9   |
| tags           | Limit Nuclei to templates w/these tags                                   | <blank> |
| templates      | Path to template file, or template directory                             | <blank> |
| severity       | Filter based on severity field available in the template                 | <blank> |
| ratelimit      | maximum number of requests to send per second                            | 150     |
| concurrency    | maximum number of templates to be executed in parallel                   | 25      |
| mode           | technology \| severe \| manual \| budget                                 | manual  |
| etags          | Tags to exclude from the scan                                            | <blank> |
| directory_only | When on, limits scan to only "directory" URLs (omit endpoints)           | True    |
| budget         | Used in budget mode to set the number of requests which will be allotted | 1       |
| retries        | Mumber of times to retry a failed request                                | 0       |
| batch_size     | The number of targets BBOT will pass to Nuclei at a time                 | 200     |

Most of these you probably will **NOT** want to change. In particular, we strongly advise against changing the version of Nuclei, as it's very likely the latest version won't work right with BBOT.

We also do not recommend changing **directory_only** mode. Because BBOT is recursive, feeding Nuclei every URL can get very out-of-hand very quickly, depending on what other modules are in use.

### Mode ###

The modes with the Nuclei module are generally in place to help you limit the number of templates you are scanning with, to make your scans quicker. 

#### Manual

This is the default setting, and will use all templates. However, if you're looking to do something particular, you might pair this with some of the pass-through options shown in the next setting.

#### Severe

**severe** mode uses only high/critical severity templates. It also excludes the intrusive tag. This is intended to be a shortcut for times when you need to rapidly identify high severity vulnerabilities but can't afford the full scan. Because most templates are INFO, LOW, or MEDIUM, your scan will finish much faster.

#### Technology

This is equivalent to the Nuclei '-as' scan option. It only use templates that match detected technologies, using wappalyzer-based signatures. This can be a nice way to run a light-weight scan that still has a chance to find some good vulnerabilities.

#### Budget

Budget mode is unique to BBOT. ​

For larger scans with thousands of targets, doing a FULL Nuclei scan (1000s of Requests) for each is not realistic. ​
As an alternative to the other modes, you can take advantage of Nuclei's "collapsible" template feature. ​

For only the cost of one (or more) "extra" request(s) per host, it can activate several hundred modules. These are modules which happen to look at a BaseUrl, and typically look for a specific string or other attribute. Nuclei is smart about reusing the request data when it can, and we can use this to our advantage. 

The budget parameter is the # of extra requests per host you are willing to send to "feed" Nuclei templates​ (defaults to 1).
For those times when vulnerability scanning isn't the main focus, but you want to look for easy wins.​

Of course, there is a rapidly diminishing return when you set he value to more than a handful. Eventually, this becomes 1 template per 1 budget value increase. However, in the 1-10 range there is a lot of value. This graphic should give you a rough visual idea of this concept.

![Nuclei Budget Mode](https://github.com/blacklanternsecurity/bbot/assets/24899338/08a3429c-5a73-437b-84de-27c07d85a529)


### Nuclei pass-through options

Most of the rest of the options are usually passed straight through to Nuclei when its executed. You can do things like set specific **tags** to include, (or exclude with **etags**), exactly how you'd do with Nuclei directly. You can also limit the templates with **severity**.

The **ratelimit** and **concurrency** settings default to the same defaults that Nuclei does. These are relatively sane settings, but if you are in a sensitive environment it can certainly help to turn them down.

**templates** will allow you to set your own templates directory. This can be very useful if you have your own custom templates that you want to use with BBOT.

### Example Commands

* Scan a SINGLE target with a basic port scan and web modules

`COMMAND: bbot -f web-basic -m nmap nuclei --allow-deadly -t app.evilcorp.com​`

* Scanning MULTIPLE targets

`bbot -f web-basic -m nmap nuclei --allow-deadly -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com​`

* Scanning MULTIPLE targets while performing subdomain enumeration

`bbot -f subdomain-enum web-basic -m nmap nuclei –allow-deadly -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com​`

* Scanning MULTIPLE targets on a BUDGET​

`bbot -f subdomain-enum web-basic -m nmap nuclei –allow-deadly –c modules.nuclei.mode=Budget -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com​`
