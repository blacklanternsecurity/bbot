# Lightfuzz

## Philosophy

### What is Lightfuzz?

Lightfuzz is a lightweight web vulnerability scanner built into BBOT. It is designed to find "low-hanging fruit" type vulnerabilities without much overhead and at massive scale. 

### What is Lightfuzz NOT?

Lightfuzz is not, does not attempt to be, and will never be, a replacement for a full-blown web application scanner. You should not, for example, be running Lightfuzz as a replacement for Burp Suite scanning. Burp Suite scanner will always find more (even though we can find a few things it can't).

It will also not help you *exploit* vulnerabilities. It's job is to point out vulnerabilities, or likely vulnerabilities, or potential vulnerabilities, and then pass them off to you. A great deal of the overhead with traditional scanners comes in the confirmation phase, or in testing exploitation payloads. 

So for example, Lightfuzz may detect an XSS vulnerability for you. But its NOT going to help you figure out which tag you need to use to get around a security filter, or give you any kind of a final payload. It's simply going to tell you that the contents of a given GET parameter are being reflected and that it was able to render an unmodified HTML tag. The rest is up to you.

### False Positives

Significant work has gone into minimizing false positives. However, due to the nature of how Lightfuzz works, they are a reality. Random hiccups in network connectivity can cause them in some cases, odd WAF behavior can account for others. 

If you see a false positive that you feel is occuring too often or could easily be prevented, please open a GitHub issue and we will take a look!

## Modules

Lightfuzz is divided into numerous "submodules". These would typically be ran all together, but they can be configured to be run individually or in any desired configuration. This would be done with the aide of a `preset`, more on those in a moment.

### `cmdi` (Command Injection)
    - Finds output-based on blind out-of-band (via `Interactsh`) command injections
### `crypto` (Cryptography)
    - Identifies cryptographic parameters that have a tangable effect on the application
    - Can identify padding oracle vulnerabilities
    - Can identify hash length extention vulnerabilities
### `path` (Path Traversal)
    - Can find arbitrary file read / local-file include vulnerabilities, based on relative path traversal or with absolute paths
### `serial` (Deserialization)
    - Can identify the active deserialization of a variety of deserialization types across several platforms
### `sqli` (SQL Injection)
    - Error Based SQLi Detection
    - Blind time-delay SQLi Detection
### `ssti` (Server-side Template Injection)
    - Can find basic server-side template injection
### `xss` (Cross-site Scripting)
    - Can find a variety of XSS types, across several different contexts (between-tags, attribute, Javascript-based)
## Presets 

Lightfuzz comes with a few pre-defined presets. The first thing to know is that, unless you really know BBOT inside and out, we recommend using one of them. This because to be successful, Lightfuzz needs to change a lot of very important BBOT settings. These include:

* Turning the web spider on, and setting a reasonable web spider distance and depth.
```
  web:
    spider_distance: 3
    spider_depth: 4
```

* Setting `url_querystring_remove` to False. By default, BBOT strips away querystings, so in order to FUZZ GET parameters, that default has to be disabled.
```
url_querystring_remove: False
```
* Setting the `excavate` internal module to retain querystrings when it finds new URLs
```
    excavate:
      retain_querystring: True
```
* Enabling several other complimentary modules. Specifically, `hunt` and `reflected_parameters` can be useful companion modules that also be useful when `WEB_PARAMETER` events are being emitted.

If you don't want to dive into those details, and we don't blame you, here are the built-in preset options and what you need to know about the differences.

# -p lightfuzz

This is the default setting, and it enables all submodules. It changes all of the essential BBOT settings to make Lightfuzz work, without too many extras. However it is important to note that it **DISABLES FUZZING POST REQUESTS**. This is because this type of request is the most intrusive, and the most likely to cause problems, especially if it's ran against an internal network. 

# -p lightfuzz-intense

* Increases the web spider settings a bit from the default.
* Adds in the **Param Miner** suite of modules to try and find new parameters to fuzz via brute-force
* Enables fuzzing of POST parameters

# -p lightfuzz-max

Everything included in `lightfuzz-intense`, plus:

* Query string collapsing turned OFF. Normally, multiple instances of the same parameter (e.g., foo=bar and foo=bar2) are collapsed into one for fuzzing. With `lightfuzz-max`, each instance is fuzzed individually.
* Force common headers enabled - Fuzz certain common header parameters, even if we didn't discover them

These settings aren't typically desired as they add significant time to the scan.

# -p lightfuzz-xss

This is a special Lightfuzz preset that focuses entirely on XSS, to make XSS hunting as fast as possible. It is an example of how to make a preset that focuses on specific submodules. It also includes the `paramminer-getparams` module to help find undocumented parameters to fuzz. 

# -p lightfuzz-min

This preset excludes all extra modules, dials down all the settings, and tests only submodules for the most common vulnerabilities. 

# Usage

With the presets in mind, usage is incredibly simple. In most cases you will just do the following:

```
bbot -p lightfuzz -t targets.txt
```

It's really that simple. Almost all output from Lightfuzz will be in the form of a `FINDING`, as opposed to a `VULNERABILITY`, with a couple of exceptions. This is because, as was explained, the nature of the findings are that they are typically unconfirmed and will require work on your part to do so.

If you wanted a specific submodule:

```
bbot -p lightfuzz -t targets.txt -c modules.lightfuzz.enabled_submodules[xss]
```