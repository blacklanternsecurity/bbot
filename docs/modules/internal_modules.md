# List of Modules

## What are internal modules?

Internal modules are just like regular modules, except that they run all the time. They do not have to be explicitly enabled. They can, however, be explicitly disabled if needed.

Turning them off is simple, a root-level config option is present which can be set to False to disable them:

```
# Infer certain events from others, e.g. IPs from IP ranges, DNS_NAMEs from URLs, etc.
speculate: True
# Passively search event data for URLs, hostnames, emails, etc.
excavate: True
# Summarize activity at the end of a scan
aggregate: True
# DNS resolution
dnsresolve: True
# Cloud provider tagging
cloudcheck: True
```

These modules are executing core functionality that is normally essential for a typical BBOT scan. Let's take a quick look at each one's functionality:

### aggregate

Summarize statistics at the end of a scan. Disable if you don't want to see this table.

### cloud

The cloud module looks at events and tries to determine if they are associated with a cloud provider and tags them as such, and can also identify certain cloud resources

### dns

The DNS internal module controls the basic DNS resolution the BBOT performs, and all of the supporting machinery like wildcard detection, etc.

### excavate

The excavate internal module designed to passively extract valuable information from HTTP response data. It primarily uses YARA regexes to extract information, with various events being produced from the post-processing of the YARA results.

Here is a summary of the data it produces:

#### URLs

By extracting URLs from all visited pages, this is actually already half of a web-spider. The other half is recursion, which is baked in to BBOT from the ground up. Therefore, protections are in place by default in the form of `web_spider_distance` and `web_spider_depth` settings. These settings govern restrictions to URLs recursively harvested from HTTP responses, preventing endless runaway scans. However, in the right situation the controlled use of a web-spider is extremely powerful.

#### Parameter Extraction

Parameter Extraction
The parameter extraction functionality identifies and extracts key web parameters from HTTP responses, and produced `WEB_PARAMETER` events. This includes parameters found in GET and POST requests, HTML forms, and jQuery requests. Currently, these are only used by the `hunt` module, and by the `paramminer` modules, to a limited degree. However, future functionality will make extensive use of these events.

#### Email Extraction

Detect email addresses within HTTP_RESPONSE data.

#### Error Detection

Scans for verbose error messages in HTTP responses and raw text data. By identifying specific error signatures from various programming languages and frameworks, this feature helps uncover misconfigurations, debugging information, and potential vulnerabilities. This insight is invaluable for identifying weak points or anomalies in web applications.

#### Content Security Policy (CSP) Extraction
The CSP extraction capability focuses on extracting domains from Content-Security-Policy headers. By analyzing these headers, BBOT can identify additional domains which can get fed back into the scan.

#### Serialization Detection
Serialized objects are a common source of serious security vulnerabilities. Excavate aims to detect those used in Java, .NET, and PHP applications.

#### Functionality Detection
Looks for specific web functionalities such as file upload fields and WSDL URLs. By identifying these elements, BBOT can pinpoint areas of the application that may require further scrutiny for security vulnerabilities.

#### Non-HTTP Scheme Detection
The non-HTTP scheme detection capability extracts URLs with non-HTTP schemes, such as ftp, mailto, and javascript. By identifying these URLs, BBOT can uncover additional vectors for attack or information leakage.

#### Custom Yara Rules

Excavate supports the use of custom YARA rules, which will be added to the other rules before the scan start. For more info, view this.

### speculate

Speculate is all about inferring one data type from another, particularly when certain tools like port scanners are not enabled. This is essential functionality for most BBOT scans, allowing for the discovery of web resources when starting with a DNS-only target list without a port scanner. It bridges gaps in the data, providing a more comprehensive view of the target by leveraging existing information.

* IP_RANGE: Converts an IP range into individual IP addresses and emits them as IP_ADDRESS events.
* DNS_NAME: Generates parent domains from DNS names.
* URL and URL_UNVERIFIED: Infers open TCP ports from URLs and speculates on sub-directory URLs.
* General URL Speculation: Emits URL_UNVERIFIED events for URLs not already in the event's history.
* IP_ADDRESS / DNS_NAME: Infers open TCP ports if active port scanning is not enabled.
* ORG_STUB: Derives organization stubs from TLDs, social stubs, or Azure tenant names and emits them as ORG_STUB events.
* USERNAME: Converts usernames to email addresses if they validate as such.
