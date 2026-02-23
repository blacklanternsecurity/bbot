# BBOT modules for attack-surface monitoring
This file groups BBOT modules into practical monitoring categories. For each module: what it does (1 sentence), whether it needs an API key, whether a *free/limited* test option is commonly available (verify with the vendor), and safer knobs for the more intense modules.
**Intensity legend:** Low (passive) → Medium (active) → High (aggressive) → Very high (deadly).
## Internal (always-on)
These run automatically unless disabled in config; they are core to discovery correlation and enrichment.
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| aggregate | Summarize statistics at the end of a scan | No | N/A | Low (passive) |  |
| cloudcheck | Tag events by cloud provider, identify cloud resources like storage buckets | No | N/A | Varies |  |
| dnsresolve | Perform DNS resolution | No | N/A | Varies |  |
| excavate | Passively extract juicy tidbits from scan data | No | N/A | Low (passive) |  |
| speculate | Derive certain event types from others by common sense | No | N/A | Low (passive) |  |
| unarchive | Extract different types of files into folders on the filesystem | No | N/A | Low (passive) |  |

## Outputs (storage/alerts)
Use outputs to persist state (DB/NDJSON) and to send alerts (Slack/Teams/HTTP/Splunk). For monitoring, persistence + diffing is the key.
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| asset_inventory | Merge hosts, open ports, technologies, findings, etc. into a single asset inventory CSV | No | N/A | Varies |  |
| csv | Output to CSV | No | N/A | Varies |  |
| discord | Message a Discord channel when certain events are encountered | No | N/A | Varies |  |
| emails | Output any email addresses found belonging to the target domain | No | N/A | Varies |  |
| http | Send every event to a custom URL via a web request | No | N/A | Varies |  |
| json | Output to Newline-Delimited JSON (NDJSON) | No | N/A | Varies |  |
| mysql | Output scan data to a MySQL database | No | N/A | Varies |  |
| neo4j | Output to Neo4j | No | N/A | Varies |  |
| nmap_xml | Output to Nmap XML | No | N/A | Varies |  |
| postgres | Output scan data to a SQLite database | No | N/A | Varies |  |
| python | Output via Python API | No | N/A | Varies |  |
| slack | Message a Slack channel when certain events are encountered | No | N/A | Varies |  |
| splunk | Send every event to a splunk instance through HTTP Event Collector | No | N/A | Varies |  |
| sqlite | Output scan data to a SQLite database | No | N/A | Varies |  |
| stdout | Output to text | No | N/A | Varies |  |
| subdomains | Output only resolved, in-scope subdomains | No | N/A | Varies |  |
| teams | Message a Teams channel when certain events are encountered | No | N/A | Varies |  |
| txt | Output to text | No | N/A | Varies |  |
| web_parameters | Output WEB_PARAMETER names to a file | No | N/A | Varies |  |
| web_report | Create a markdown report with web assets | No | N/A | Varies |  |
| websocket | Output to websockets | No | N/A | Varies |  |

## Domain / subdomain discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| affiliates | Summarize affiliate domains at the end of a scan | No | N/A | Low (passive) |  |
| anubisdb | Query jldc.me's database for subdomains | No | N/A | Low (passive) |  |
| asn | Query ripe and bgpview.io for ASNs | No | N/A | Low (passive) |  |
| bevigil | Retrieve OSINT data from mobile applications using BeVigil | Yes | Unknown; check provider for free/trial quota. | Low (passive) |  |
| bufferoverrun | Query BufferOverrun's TLS API for subdomains | Yes | Unknown; check provider for free/trial quota. | Low (passive) |  |
| builtwith | Query Builtwith.com for subdomains | Yes | Usually paid; check vendor for trial. | Low (passive) |  |
| c99 | Query the C99 API for subdomains | Yes | Unknown; check provider for free/trial quota. | Low (passive) |  |
| censys_dns | Query the Censys API for subdomains | Yes | Often yes: Censys typically offers a free/limited tier (verify). | Low (passive) |  |
| certspotter | Query Certspotter's API for subdomains | No | N/A | Low (passive) |  |
| chaos | Query ProjectDiscovery's Chaos API for subdomains | Yes | Often yes: ProjectDiscovery Chaos usually has a free/community quota (verify). | Low (passive) |  |
| crt | Query crt.sh (certificate transparency) for subdomains | No | N/A | Low (passive) |  |
| crt_db | Query crt.sh (certificate transparency) for subdomains via PostgreSQL | No | N/A | Low (passive) |  |
| digitorus | Query certificatedetails.com for subdomains | No | N/A | Low (passive) |  |
| dnsbrute | Brute-force subdomains with massdns + static wordlist | No | N/A | High (aggressive) | Safer: use smaller wordlists / fewer mutations and restrict to explicit in-scope domains. |
| dnsbrute_mutations | Brute-force subdomains with massdns + target-specific mutations | No | N/A | High (aggressive) | Safer: same as `dnsbrute`, and keep mutation lists small. |
| dnscommonsrv | Check for common SRV records | No | N/A | Medium (active) |  |
| dnsdumpster | Query dnsdumpster for subdomains | No | N/A | Low (passive) |  |
| fullhunt | Query the fullhunt.io API for subdomains | Yes | Usually paid; check vendor for trial. | Low (passive) |  |
| hackertarget | Query the hackertarget.com API for subdomains | No | N/A | Low (passive) |  |
| ipneighbor | Look beside IPs in their surrounding subnet | No | N/A | High (aggressive) | Safer: only enable when you explicitly want neighbor enumeration; keep scan scope tight. |
| leakix | Query leakix.net for subdomains | No | N/A | Low (passive) |  |
| myssl | Query myssl.com's API for subdomains | No | N/A | Low (passive) |  |
| otx | Query otx.alienvault.com for subdomains | Yes | Yes: AlienVault OTX API key is typically free (community, rate-limited). | Low (passive) |  |
| passivetotal | Query the PassiveTotal API for subdomains | Yes | Usually paid (enterprise); check vendor for evaluation. | Low (passive) |  |
| rapiddns | Query rapiddns.io for subdomains | No | N/A | Low (passive) |  |
| securitytrails | Query the SecurityTrails API for subdomains | Yes | Usually paid; check if trial is available. | Low (passive) |  |
| shodan_dns | Query Shodan for subdomains | Yes | Usually paid for full API access; check Shodan plans/trial credits. | Low (passive) |  |
| sitedossier | Query sitedossier.com for subdomains | No | N/A | Low (passive) |  |
| subdomaincenter | Query subdomain.center's API for subdomains | No | N/A | Low (passive) |  |
| subdomainradar | Query the Subdomain API for subdomains | Yes | Unknown; check provider for free/trial quota. | Low (passive) |  |
| trickest | Query Trickest's API for subdomains | Yes | Unknown; check provider for free/trial quota. | Low (passive) |  |
| thc_cnames | Query ip.thc.org for domains CNAME'd to a target domain | No | N/A | Low (passive) |  |
| thc_rdns | Query ip.thc.org reverse DNS by IP | No | N/A | Low (passive) |  |
| thc_subdomains | Query ip.thc.org for subdomains | No | N/A | Low (passive) |  |
| urlscan | Query urlscan.io for subdomains | No | N/A | Low (passive) |  |
| viewdns | Query viewdns.info's reverse whois for related domains | No | N/A | Low (passive) |  |
| virustotal | Query VirusTotal's API for subdomains | Yes | Often yes: free VirusTotal API key exists but is rate-limited (verify current limits). | Low (passive) |  |
| wayback | Query archive.org's API for subdomains | No | N/A | Low (passive) |  |

## Email / identity discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| dehashed | Execute queries against dehashed.com for exposed credentials | Yes | Usually paid; check vendor for trial. | Low (passive) |  |
| dnscaa | Check for CAA records | No | N/A | Low (passive) |  |
| emailformat | Query email-format.com for email addresses | No | N/A | Low (passive) |  |
| hunterio | Query hunter.io for emails | Yes | Often yes: free plan/trial usually available with small quotas (verify). | Low (passive) |  |
| leaklookup | Query leak-lookup.com for leaked credentials and crack hashes | Yes | Usually paid; check vendor for trial. | Low (passive) |  |
| pgp | Query common PGP servers for email addresses | No | N/A | Low (passive) |  |
| skymem | Query skymem.info for email addresses | No | N/A | Low (passive) |  |
| snovio | Query Snov.io Domain Search v2 for company email addresses | Yes | Often yes: free/limited tier usually available (verify current quotas). | Low (passive) |  |
| sslcert | Visit open ports and retrieve SSL certificates | No | N/A | Medium (active) |  |

## Social discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| social | Look for social media links in webpages | No | N/A | Low (passive) |  |

## Code / repo / artifact discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| apkpure | Download android applications from apkpure.com | No | N/A | Low (passive) |  |
| code_repository | Look for code repository links in webpages | No | N/A | Low (passive) |  |
| docker_pull | Download images from a docker repository | No | N/A | Low (passive) |  |
| dockerhub | Search for docker repositories of discovered orgs/usernames | No | N/A | Low (passive) |  |
| git | Check for exposed .git repositories | No | N/A | Medium (active) |  |
| git_clone | Clone code github repositories | No | N/A | Low (passive) |  |
| gitdumper | Download a leaked .git folder recursively or by fuzzing common names | No | N/A | Low (passive) |  |
| ggshield | Find hardcoded secrets using GitGuardian ggshield | No (optional key) | Yes: GitGuardian usually offers a free tier/trial (verify). | Low (passive) |  |
| github_codesearch | Query Github's API for code containing the target domain name | Yes | Yes: GitHub personal token (free, rate-limited). | Low (passive) |  |
| github_org | Query Github's API for organization and member repositories | No | N/A | Low (passive) |  |
| github_usersearch | Query Github's API for users with emails matching in scope domains that may not be discoverable by listing members of the organization. | Yes | Yes: GitHub personal token (free, rate-limited). | Low (passive) |  |
| github_workflows | Download a github repositories workflow logs and workflow artifacts | Yes | Yes: GitHub personal token (free, rate-limited). | Low (passive) |  |
| gitleaks | Find hardcoded secrets using Gitleaks | No | N/A | Low (passive) |  |
| gitlab_com | Enumerate GitLab SaaS (gitlab.com/org) for projects and groups | No | N/A | Medium (active) |  |
| gitlab_onprem | Detect self-hosted GitLab instances and query them for repositories | No | N/A | Medium (active) |  |
| google_playstore | Search for android applications on play.google.com | No | N/A | Low (passive) |  |
| jadx | Decompile APKs and XAPKs using JADX | No | N/A | Low (passive) |  |
| kingfisher | Find hardcoded secrets using Kingfisher | No | N/A | Low (passive) |  |
| noseyparker | Find hardcoded secrets using Nosey Parker | No | N/A | Low (passive) |  |
| postman | Query Postman's API for related workspaces, collections, requests and download them | No | N/A | Low (passive) |  |
| postman_download | Download workspaces, collections, requests from Postman | No | N/A | Low (passive) |  |
| trufflehog | TruffleHog is a tool for finding credentials | No | N/A | Low (passive) |  |

## Cloud / SaaS / storage discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| azure_realm | Retrieves the "AuthURL" from login.microsoftonline.com/getuserrealm | No | N/A | Low (passive) |  |
| azure_tenant | Query Azure via azmap.dev for tenant sister domains | No | N/A | Low (passive) |  |
| baddns_direct | Check for unusual subdomain / service takeover edge cases that require direct detection | No | N/A | Medium (active) |  |
| baddns_zone | Check hosts for DNS zone transfers and NSEC walks | No | N/A | Medium (active) |  |
| bucket_amazon | Check for S3 buckets related to target | No | N/A | Medium (active) |  |
| bucket_digitalocean | Check for DigitalOcean spaces related to target | No | N/A | Medium (active) |  |
| bucket_file_enum | Works in conjunction with the filedownload module to download files from open storage buckets. Currently supported cloud providers: AWS, DigitalOcean | No | N/A | Low (passive) |  |
| bucket_firebase | Check for open Firebase databases related to target | No | N/A | Medium (active) |  |
| bucket_google | Check for Google object storage related to target | No | N/A | Medium (active) |  |
| bucket_microsoft | Check for Azure storage blobs related to target | No | N/A | Medium (active) |  |
| dnsbimi | Check DNS_NAME's for BIMI records to find image and certificate hosting URL's | No | N/A | Low (passive) |  |
| dnstlsrpt | Check for TLS-RPT records | No | N/A | Low (passive) |  |
| httpx | Visit webpages. Many other modules rely on httpx | No | N/A | Medium (active) |  |
| oauth | Enumerate OAUTH and OpenID Connect services | No | N/A | Medium (active) |  |
| securitytxt | Check for security.txt content | No | N/A | Medium (active) |  |

## Port discovery
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| naabu | Port scan with naabu (ProjectDiscovery). By default, scans top 100 ports. | No | N/A | Medium (active) |  |
| portscan | Port scan with masscan. By default, scans top 100 ports. | No | N/A | Medium (active) |  |
| shodan_idb | Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities | No | N/A | Low (passive) |  |

## Service fingerprinting / enrichment
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| fingerprintx | Fingerprint exposed services like RDP, SSH, MySQL, etc. | No | N/A | Medium (active) |  |

## Web enumeration (basic)
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| badsecrets | Library for detecting known or weak secrets across many web frameworks | No | N/A | Medium (active) |  |
| filedownload | Download common filetypes such as PDF, DOCX, PPTX, etc. | No | N/A | Medium (active) |  |
| graphql_introspection | Perform GraphQL introspection on a target | No | N/A | Medium (active) |  |
| iis_shortnames | Check for IIS shortname vulnerability | No | N/A | Medium (active) |  |
| ntlm | Watch for HTTP endpoints that support NTLM authentication | No | N/A | Medium (active) |  |
| robots | Look for and parse robots.txt | No | N/A | Medium (active) |  |

## Web enumeration (thorough)
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| ajaxpro | Check for potentially vulnerable Ajaxpro instances | No | N/A | Medium (active) |  |
| aspnet_bin_exposure | Check for ASP.NET Security Feature Bypasses (CVE-2023-36899 and CVE-2023-36560) | No | N/A | Medium (active) |  |
| bypass403 | Check 403 pages for common bypasses | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| dotnetnuke | Scan for critical DotNetNuke (DNN) vulnerabilities | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| ffuf_shortnames | Use ffuf in combination IIS shortnames | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| generic_ssrf | Check for generic SSRFs | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| host_header | Try common HTTP Host header spoofing techniques | No | N/A | High (aggressive) | Safer: keep `interactsh_disable: true` if you cannot allow callbacks; run only in-scope. |
| hunt | Watch for commonly-exploitable HTTP parameters | No | N/A | Medium (active) |  |
| lightfuzz | Find Web Parameters and Lightly Fuzz them using a heuristic based scanner | No | N/A | Very high (deadly) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| reflected_parameters | Highlight parameters that reflect their contents in response body | No | N/A | Medium (active) |  |
| retirejs | Detect vulnerable/out-of-date JavaScript libraries | No | N/A | Medium (active) |  |
| smuggler | Check for HTTP smuggling | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| telerik | Scan for critical Telerik vulnerabilities | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| url_manipulation | Attempt to identify URL parsing/routing based vulnerabilities | No | N/A | High (aggressive) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |

## Web parameter mining
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| paramminer_cookies | Smart brute-force to check for common HTTP cookie parameters | No | N/A | High (aggressive) | Safer: small wordlist; run only on key endpoints; keep scope tight. |
| paramminer_getparams | Use smart brute-force to check for common HTTP GET parameters | No | N/A | High (aggressive) | Safer: keep `skip_boring_words: true` and avoid huge wordlists; run only on key endpoints. |
| paramminer_headers | Use smart brute-force to check for common HTTP header parameters | No | N/A | High (aggressive) | Safer: small wordlist; run only on key endpoints; keep scope tight. |

## Web screenshots
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| gowitness | Take screenshots of webpages | No | N/A | Medium (active) |  |

## Takeover / misconfig detection
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| baddns | Check hosts for domain/subdomain takeovers | No | N/A | Medium (active) |  |

## Other
| Module | What it does | Needs API key | Free/limited test option? | Intensity | Safer settings (if intense) |
|---|---|---:|---|---|---|
| censys_ip | Query the Censys API for hosts by IP address | Yes | Often yes: Censys typically offers a free/limited tier (verify). | Low (passive) |  |
| credshed | Send queries to your own credshed server to check for known credentials of your targets | Yes | Yes if self-hosted: key is for your own credshed instance. | Low (passive) |  |
| extractous | Module to extract data from files | No | N/A | Low (passive) |  |
| ffuf | A fast web fuzzer written in Go | No | N/A | Very high (deadly) | Safer: keep `lines` small, set `max_depth: 0`, and set a low `rate`. |
| ipwhois | Query ipwho.is API for geolocation information. | No | Yes: free keyless endpoint for basic lookups. | Low (passive) |  |
| ipstack | Query IPStack's GeoIP API | Yes | Often yes: may offer free tier/trial (verify). | Low (passive) |  |
| legba | Credential bruteforcing supporting various services. | No | N/A | Very high (deadly) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| medusa | Medusa SNMP bruteforcing with v1, v2c and R/W check. | No | N/A | Very high (deadly) | Safer: reduce concurrency/rate, keep scope tight, and run only on newly discovered assets. |
| newsletters | Searches for Newsletter Submission Entry Fields on Websites | No | N/A | Medium (active) |  |
| nuclei | Fast and customisable vulnerability scanner | No | N/A | Very high (deadly) | Safer: use `mode: severe` or `mode: budget`, lower `ratelimit`/`concurrency`, and keep `directory_only: true`. |
| portfilter | Filter out unwanted open ports from cloud/CDN targets | No | N/A | Low (passive) |  |
| vhost | Fuzz for virtual hosts | No | N/A | Very high (deadly) | Safer: keep `lines` small and only run on a curated URL list. |
| wafw00f | Web Application Firewall Fingerprinting Tool | No | N/A | High (aggressive) | Safer: run only on confirmed web URLs and limit concurrency globally. |
| wpscan | Wordpress security scanner. Highly recommended to use an API key for better results. | No | N/A | High (aggressive) | Safer: keep `threads` low, do not set `force: true` unless needed. |
