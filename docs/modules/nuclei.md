# Nuclei

## Overview

BBOT integrates with [Nuclei](https://github.com/projectdiscovery/nuclei), an open-source web vulnerability scanner by Project Discovery. This is one of the ways BBOT makes it possible to go from a single target domain/IP all the way to confirmed vulnerabilities, in one scan.

![Nuclei Killchain](https://github.com/blacklanternsecurity/bbot/assets/24899338/7174c4ba-4a6e-4596-bb89-5a0c5f5abe74)


* The BBOT Nuclei module ingests **[URL]** events and emits events of type **[FINDING]**
* Findings will inherit their severity from the Nuclei templates

## Default Behavior

* By default, only "directory URLs" (URLs ending in a slash) will be scanned, but ALL templates will be used (**BE CAREFUL!**)
* Because it's aggressive and potentially destructive, Nuclei is tagged as both **loud** and **invasive**. BBOT will warn you before starting the scan, but no special flag is needed to enable it.

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
| Config Option                         | Type                                                | Description                                                                                                                                                                                                                                                                                                                    | Default   |
|---------------------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| modules.nuclei.batch_size             | int                                                 | Number of targets to send to Nuclei per batch (default 200)                                                                                                                                                                                                                                                                    | 200       |
| modules.nuclei.budget                 | int                                                 | Used in budget mode to set the number of allowed requests per host                                                                                                                                                                                                                                                             | 1         |
| modules.nuclei.concurrency            | int                                                 | maximum number of templates to be executed in parallel (default 25)                                                                                                                                                                                                                                                            | 25        |
| modules.nuclei.directory_only         | bool                                                | Filter out 'file' URL event (default True)                                                                                                                                                                                                                                                                                     | True      |
| modules.nuclei.etags                  | str                                                 | tags to exclude from the scan                                                                                                                                                                                                                                                                                                  |           |
| modules.nuclei.exclude_ids            | str                                                 | Exclude templates with the given IDs                                                                                                                                                                                                                                                                                           |           |
| modules.nuclei.exclude_severity       | str                                                 | Filter out templates with the given severities                                                                                                                                                                                                                                                                                 |           |
| modules.nuclei.include_tags           | str                                                 | tags to run even though nuclei excludes them by default (e.g. dos, fuzz, bruteforce)                                                                                                                                                                                                                                           |           |
| modules.nuclei.mode                   | Literal['manual', 'technology', 'severe', 'budget'] | manual &#124; technology &#124; severe &#124; budget. Technology: Only activate based on technology events that match nuclei tags (nuclei -as mode). Manual (DEFAULT): Fully manual settings. Severe: Only critical and high severity templates without intrusive. Budget: Limit Nuclei to a specified number of HTTP requests | manual    |
| modules.nuclei.module_timeout         | int                                                 | Max time in seconds to spend handling each batch of events                                                                                                                                                                                                                                                                     | 21600     |
| modules.nuclei.new_templates          | bool                                                | Only run templates added in the latest templates release                                                                                                                                                                                                                                                                       | False     |
| modules.nuclei.new_templates_versions | str                                                 | Only run templates added in the given templates releases, e.g. 'v10.4.8,v10.4.9'                                                                                                                                                                                                                                               |           |
| modules.nuclei.profile                | str                                                 | nuclei template profile to run (built-in profile id, or path to a profile file)                                                                                                                                                                                                                                                |           |
| modules.nuclei.protocol_types         | str                                                 | Only run templates of the given protocol types (http, dns, ssl, tcp, javascript, etc.)                                                                                                                                                                                                                                         |           |
| modules.nuclei.ratelimit              | int                                                 | maximum number of requests to send per second (default 150)                                                                                                                                                                                                                                                                    | 150       |
| modules.nuclei.retries                | int                                                 | number of times to retry a failed request (default 0)                                                                                                                                                                                                                                                                          | 0         |
| modules.nuclei.severity               | str                                                 | Filter based on severity field available in the template.                                                                                                                                                                                                                                                                      |           |
| modules.nuclei.silent                 | bool                                                | Don't display nuclei's banner or status messages                                                                                                                                                                                                                                                                               | False     |
| modules.nuclei.tags                   | str                                                 | execute a subset of templates that contain the provided tags                                                                                                                                                                                                                                                                   |           |
| modules.nuclei.template_condition     | str                                                 |` expression to filter templates by, e.g. "epss_score>=0.1 && max_request<=3"                                                                                                                                                                                                                                                    `|           |
| modules.nuclei.template_ids           | str                                                 | Only run templates with the given IDs (wildcards allowed)                                                                                                                                                                                                                                                                      |           |
| modules.nuclei.templates              | str                                                 | template or template directory paths to include in the scan                                                                                                                                                                                                                                                                    |           |
| modules.nuclei.version                | str                                                 | nuclei version                                                                                                                                                                                                                                                                                                                 | 3.11.1    |
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

This is equivalent to the Nuclei '-as' scan option. It only uses templates that match detected technologies, using wappalyzer-based signatures. This can be a nice way to run a light-weight scan that still has a chance to find some good vulnerabilities.

#### Budget

Budget mode is unique to BBOT.

For larger scans with thousands of targets, doing a FULL Nuclei scan (1000s of Requests) for each is not realistic.
As an alternative to the other modes, you can take advantage of Nuclei's "collapsible" template feature.

For only the cost of one (or more) "extra" request(s) per host, it can activate several hundred modules. These are modules which happen to look at a BaseUrl, and typically look for a specific string or other attribute. Nuclei is smart about reusing the request data when it can, and we can use this to our advantage.

The budget parameter is the # of extra requests per host you are willing to send to "feed" Nuclei templates (defaults to 1).
For those times when vulnerability scanning isn't the main focus, but you want to look for easy wins.

To give a sense of scale: against a recent template set, a budget of 1 selects roughly 1,300 templates for about 2 requests per host, and a budget of 10 selects roughly 1,500. There is a rapidly diminishing return past a handful, and eventually this becomes 1 template per 1 budget value increase. However, in the 1-10 range there is a lot of value. This graphic should give you a rough visual idea of this concept.

![Nuclei Budget Mode](https://github.com/blacklanternsecurity/bbot/assets/24899338/08a3429c-5a73-437b-84de-27c07d85a529)

Note that Nuclei's own `metadata.max-request` field is *not* the same thing, and `template_condition` is not a substitute for budget mode. `max-request` caps the requests made by each individual template, whereas budget mode caps the total requests made against each host by selecting templates that all land on the same handful of URLs.

### Nuclei pass-through options

Most of the rest of the options are usually passed straight through to Nuclei when its executed. You can do things like set specific **tags** to include, (or exclude with **etags**), exactly how you'd do with Nuclei directly. You can also limit the templates with **severity**.

The **ratelimit** and **concurrency** settings default to the same defaults that Nuclei does. These are relatively sane settings, but if you are in a sensitive environment it can certainly help to turn them down.

**templates** will allow you to set your own templates directory. This can be very useful if you have your own custom templates that you want to use with BBOT.

### Limiting templates

These options stack on top of whichever **mode** you've chosen, and on top of each other. Nuclei intersects them, so combining two filters gives you the templates that satisfy both.

**exclude_severity** is the counterpart to **severity**. Dropping `info` on its own removes about 5,000 templates, most of which are detections rather than vulnerabilities.

**template_ids** and **exclude_ids** select or drop templates by ID, and **template_ids** accepts wildcards (e.g. `CVE-2024-*`). **exclude_ids** is the clean way to suppress a template that false-positives against a particular client, without maintaining your own copy of the template tree.

**protocol_types** restricts the scan to given protocols: `http`, `dns`, `ssl`, `tcp`, `javascript`, `code`, `file`, `headless`, `websocket`, `whois`, `workflow`.

**include_tags** force-runs tags that Nuclei excludes by default. Nuclei ships an ignore list (`dos`, `local`, `fuzz`, `bruteforce`, `txt-service`) that applies before any option here, and this is the only way to reach those templates. Be careful with `fuzz` in particular: those templates carry very large payload lists and account for the overwhelming majority of Nuclei's potential request volume.

**profile** selects a Nuclei template profile, which is a curated bundle of filter settings. You can give it the id of one of the profiles that ships with nuclei-templates (`recommended`, `pentest`, `cves`, `kev`, `misconfigurations`, `wordpress`, and more -- run `nuclei -tpl` for the full list), or a path to a profile file of your own. The `recommended` profile is a good default: alongside a severity floor it carries a maintained list of templates known to produce false positives, and that list updates along with the templates.

**template_condition** is passed to Nuclei's `-template-condition` and filters on the template's metadata. Useful fields include `severity`, `max_request`, `epss_score`, `epss_percentile`, `cvss_score`, `cve_id`, `cwe_id`, `cpe`, `vendor`, `product` and `tags`. For example, `epss_score >= 0.1 || contains(tags, 'kev')` limits the scan to vulnerabilities with real-world exploitation evidence. Be aware that Nuclei treats an unrecognized field name as a non-match rather than an error, so BBOT counts the matching templates at startup and refuses to scan if the expression matches nothing.

**new_templates** limits the scan to templates added in the most recent nuclei-templates release, which is typically 100-130 templates. **new_templates_versions** does the same for specific releases, e.g. `v10.4.8,v10.4.9`. These are handy for re-scanning a target you've already covered, to see only what's new.

### Example Commands

```bash
# Scan a SINGLE target with a basic port scan and web modules
bbot -f web -m portscan nuclei -t app.evilcorp.com
```

```bash
# Scanning MULTIPLE targets
bbot -f web -m portscan nuclei -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```

```bash
# Scanning MULTIPLE targets while performing subdomain enumeration
bbot -f subdomain-enum web -m portscan nuclei -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```

```bash
# Scanning MULTIPLE targets on a BUDGET
bbot -f subdomain-enum web -m portscan nuclei -c modules.nuclei.mode=budget -t app1.evilcorp.com app2.evilcorp.com app3.evilcorp.com
```
