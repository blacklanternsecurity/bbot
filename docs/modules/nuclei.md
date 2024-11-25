# Nuclei

## Overview

BBOT integrates with [Nuclei](https://github.com/projectdiscovery/nuclei), an open-source web vulnerability scanner by Project Discovery. This is one of the ways BBOT makes it possible to go from a single target domain/IP all the way to confirmed vulnerabilities, in one scan. 

![Nuclei Killchain](https://github.com/blacklanternsecurity/bbot/assets/24899338/7174c4ba-4a6e-4596-bb89-5a0c5f5abe74)


* The BBOT Nuclei module ingests **[URL]** events and emits events of type **[VULNERABILITY]** or **[FINDING]**
* Vulnerabilities will inherit their severity from the Nuclei templates
* Nuclei templates of severity INFO will be emitted as **[FINDINGS]**

## Default Behavior

* By default, only "directory URLs" (URLs ending in a slash) will be scanned, but ALL templates will be used (**BE CAREFUL!**)
* Because it's so aggressive, Nuclei is considered a **deadly** module. This means you need to use the flag **--allow-deadly** to turn it on.

## Specifying custom templates

You can specify individual nuclei templates by setting the `modules.nuclei.templates` to their comma-separated filenames:

```bash
bbot -m nuclei -c modules.nuclei.templates=http/takeovers/airee-takeover.yaml,http/takeovers/cargo-takeover.yaml
```

...or via the config:

```yaml
modules:
  nuclei:
    templates: http/takeovers/airee-takeover.yaml,http/takeovers/cargo-takeover.yaml
```

## Configuration and Options

The Nuclei module has many configuration options:

<!-- BBOT MODULE OPTIONS NUCLEI -->
| Config Option                 | Type   | Description                                                                                                                                                                                                                                                                                                                    | Default   |
|-------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| modules.nuclei.batch_size     | int    | Number of targets to send to Nuclei per batch (default 200)                                                                                                                                                                                                                                                                    | 200       |
| modules.nuclei.budget         | int    | Used in budget mode to set the number of requests which will be allotted to the nuclei scan                                                                                                                                                                                                                                    | 1         |
| modules.nuclei.concurrency    | int    | maximum number of templates to be executed in parallel (default 25)                                                                                                                                                                                                                                                            | 25        |
| modules.nuclei.directory_only | bool   | Filter out 'file' URL event (default True)                                                                                                                                                                                                                                                                                     | True      |
| modules.nuclei.etags          | str    | tags to exclude from the scan                                                                                                                                                                                                                                                                                                  |           |
| modules.nuclei.mode           | str    | manual &#124; technology &#124; severe &#124; budget. Technology: Only activate based on technology events that match nuclei tags (nuclei -as mode). Manual (DEFAULT): Fully manual settings. Severe: Only critical and high severity templates without intrusive. Budget: Limit Nuclei to a specified number of HTTP requests | manual    |
| modules.nuclei.ratelimit      | int    | maximum number of requests to send per second (default 150)                                                                                                                                                                                                                                                                    | 150       |
| modules.nuclei.retries        | int    | number of times to retry a failed request (default 0)                                                                                                                                                                                                                                                                          | 0         |
| modules.nuclei.severity       | str    | Filter based on severity field available in the template.                                                                                                                                                                                                                                                                      |           |
| modules.nuclei.silent         | bool   | Don't display nuclei's banner or status messages                                                                                                                                                                                                                                                                               | False     |
| modules.nuclei.tags           | str    | execute a subset of templates that contain the provided tags                                                                                                                                                                                                                                                                   |           |
| modules.nuclei.templates      | str    | template or template directory paths to include in the scan                                                                                                                                                                                                                                                                    |           |
| modules.nuclei.version        | str    | nuclei version                                                                                                                                                                                                                                                                                                                 | 3.3.6     |
<!-- END BBOT MODULE OPTIONS NUCLEI -->

Most of these you probably will **NOT** want to change. In particular, we advise against changing the version of Nuclei, as it's possible the latest version won't work right with BBOT.

We also do not recommend changing **directory_only** mode. This will cause Nuclei to process every URL. Because BBOT is recursive, this can get very out-of-hand very quickly, depending on which other modules are in use.

### Modes ###

The modes with the Nuclei module are generally in place to help you limit the number of templates you are scanning with, to make your scans quicker. 

#### Manual

This is the default setting, and will use all templates. However, if you're looking to do something particular, you might pair this with some of the pass-through options shown in the next setting.

#### Severe

**severe** mode uses only high/critical severity templates. It also excludes the intrusive tag. This is intended to be a shortcut for times when you need to rapidly identify high severity vulnerabilities but can't afford the full scan. Because most templates are INFO, LOW, or MEDIUM, your scan will finish much faster.

#### Technology

This is equivalent to the Nuclei '-as' scan option. It only use templates that match detected technologies, using wappalyzer-based signatures. This can be a nice way to run a light-weight scan that still has a chance to find some good vulnerabilities.

#### Budget

Budget mode is unique to BBOT.

For larger scans with thousands of targets, doing a FULL Nuclei scan (1000s of Requests) for each is not realistic. 
As an alternative to the other modes, you can take advantage of Nuclei's "collapsible" template feature. 

For only the cost of one (or more) "extra" request(s) per host, it can activate several hundred modules. These are modules which happen to look at a BaseUrl, and typically look for a specific string or other attribute. Nuclei is smart about reusing the request data when it can, and we can use this to our advantage. 

The budget parameter is the # of extra requests per host you are willing to send to "feed" Nuclei templates (defaults to 1).
For those times when vulnerability scanning isn't the main focus, but you want to look for easy wins.

Of course, there is a rapidly diminishing return when you set he value to more than a handful. Eventually, this becomes 1 template per 1 budget value increase. However, in the 1-10 range there is a lot of value. This graphic should give you a rough visual idea of this concept.

![Nuclei Budget Mode](https://github.com/blacklanternsecurity/bbot/assets/24899338/08a3429c-5a73-437b-84de-27c07d85a529)


### Nuclei pass-through options

Most of the rest of the options are usually passed straight through to Nuclei when its executed. You can do things like set specific **tags** to include, (or exclude with **etags**), exactly how you'd do with Nuclei directly. You can also limit the templates with **severity**.

The **ratelimit** and **concurrency** settings default to the same defaults that Nuclei does. These are relatively sane settings, but if you are in a sensitive environment it can certainly help to turn them down.

**templates** will allow you to set your own templates directory. This can be very useful if you have your own custom templates that you want to use with BBOT.

### Example Commands

```bash
# Scan a SINGLE target with a basic port scan and web modules
bbot -f web-basic -m portscan nuclei --allow-deadly -t app.evilcorp.com
```

```bash
# Scanning MULTIPLE targets
bbot -f web-basic -m portscan nuclei --allow-deadly -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```

```bash
# Scanning MULTIPLE targets while performing subdomain enumeration
bbot -f subdomain-enum web-basic -m portscan nuclei --allow-deadly -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```

```bash
# Scanning MULTIPLE targets on a BUDGET
bbot -f subdomain-enum web-basic -m portscan nuclei --allow-deadly -c modules.nuclei.mode=budget -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```
