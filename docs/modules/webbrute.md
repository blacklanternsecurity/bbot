# Web Brute-Force (webbrute)

## Overview

`webbrute` is BBOT's built-in web directory and file brute-forcer, similar to tools like [ffuf](https://github.com/ffuf/ffuf) or [DirBuster](https://owasp.org/www-project-dirbuster/). It discovers hidden directories and files by sending a wordlist of common path names to a target and identifying responses that differ from the baseline (i.e., the server's default response to a nonexistent path).

Unlike standalone tools, webbrute runs as part of BBOT's recursive pipeline. URLs discovered by other modules (spidering, wayback, etc.) are automatically fuzzed, and webbrute's discoveries feed back into the pipeline for further processing.

Webbrute is powered by [blasthttp](https://github.com/blacklanternsecurity/blasthttp), our custom-built native Rust HTTP engine, giving it performance comparable to ffuf.

## Quick Start

```bash
# Basic directory brute-force
bbot -t example.com -m webbrute

# With file extensions
bbot -t example.com -m webbrute -c modules.webbrute.extensions=php,asp,jsp

# Aggressive mode with larger wordlist and recursion
bbot -t example.com -p dirbust-heavy
```

## Features

### Extensions

By default, webbrute tests each word as both a bare path (`/admin`) and as a directory (`/admin/`). You can add file extensions to also test paths like `/admin.php`, `/admin.asp`, etc.

```yaml
modules:
  webbrute:
    extensions:
      - php
      - asp
      - aspx
      - jsp
```

Each extension gets its own independent baseline, so a server that behaves differently for `.php` vs `.jsp` requests is handled correctly.

### Recursive Fuzzing

With `max_depth` set above 0, webbrute will recursively fuzz directories it discovers. For example, if it finds `/admin/`, it will fuzz `/admin/` with the same wordlist to discover `/admin/config/`, and so on up to the configured depth.

```yaml
modules:
  webbrute:
    max_depth: 3
```

### Wordlists

The default wordlist is [raft-small-directories](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) from SecLists, limited to the first 5000 lines. You can specify a custom wordlist or merge multiple wordlists (duplicates are automatically removed):

```yaml
modules:
  webbrute:
    wordlist:
      - https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt
      - /path/to/custom-words.txt
    lines: 10000
```

### Rate Limiting

Webbrute respects BBOT's global `http_rate_limit` setting and also has its own per-module rate limit:

```yaml
modules:
  webbrute:
    rate: 100        # max requests per second (0 = unlimited)
    concurrency: 50  # concurrent requests per URL
```

If both a module rate and a global rate are set, the more restrictive one wins.

## WAF Detection and Avoidance

Brute-forcing through a WAF wastes time and can get your IP blocked. Webbrute handles WAFs at multiple levels:

### Pre-Scan: `avoid_wafs`

When `avoid_wafs` is enabled (the default), webbrute skips any URL whose host has been tagged as being behind a WAF by BBOT's `cloudcheck` module. This prevents wasting thousands of requests against a host that will block them.

```yaml
modules:
  webbrute:
    avoid_wafs: true  # default
```

### Baseline: WAF Block Page and 429 Detection

During baseline setup, webbrute checks whether the server's response to random paths contains known WAF block page signatures (detected via YARA rules). If the baseline itself is a WAF block page, the host is skipped immediately. The same check catches 429 (Too Many Requests) responses.

### In-Stream: WAF Page Filtering

During fuzzing, every response is checked against the same WAF YARA rules. Individual responses that match WAF signatures are silently filtered, even if they have a 200 status code. This catches WAFs that start blocking mid-scan after a burst of requests.

### Timeout Tracking

Some WAFs silently drop packets rather than returning error pages. Webbrute tracks connection failures per host across the entire scan. If a host accumulates 50 timeouts, it is blocked for the remainder of the scan, preventing the module from draining its entire wordlist against a dead connection.

## False Positive Prevention

Web brute-forcing is inherently noisy. Servers return custom error pages, dynamic content, and catch-all redirects that make it difficult to distinguish real hits from junk. Webbrute uses several layers of defense to prevent false positives.

### Baseline Filtering (HttpCompare)

Before fuzzing begins, webbrute sends two requests with random paths and uses HttpCompare (a DeepDiff-based response comparison engine) to diff them. Any positions that vary between the two (timestamps, CSRF tokens, request IDs) are marked as dynamic and excluded from future comparisons. During fuzzing, each response is compared against this baseline. Only responses that differ in non-dynamic ways (status code, headers, or body content) are considered potential hits.

This catches a common class of false positives that simpler tools miss: servers that return 200 for all paths with subtly different content (e.g., a per-request CSRF token embedded in a custom 404 page).

### Redirect-to-Root Filtering

3xx responses that redirect to `/` or the base URL are filtered. This is a common catch-all pattern where servers redirect all unknown paths to the homepage.

### Three-Layer Post-Stream Validation

Hits are collected during the response stream but are not emitted immediately. Before anything reaches the rest of the pipeline, three checks run in sequence:

1. **Canary check**: A random word is injected into the wordlist alongside the real words. If the canary word appears in the hits, it means the server is returning unique content for random paths too, and all hits are likely false positives. Everything is discarded.

2. **Mid-scan baseline validation**: After streaming completes, a fresh random URL is sent and compared against the original baseline. If it no longer matches (e.g., a WAF started blocking mid-scan, or the server's behavior changed), the baseline has drifted and the hits are unreliable. Everything is discarded.

3. **Hit cap**: If the number of hits exceeds a threshold scaled to the wordlist size (`4 * sqrt(wordlist_length)`), something has slipped past the other defenses. This catches edge cases where the server returns subtly unique content for real dictionary words but not for random strings. The host is blocked and all hits are discarded before emission.

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `wordlist` | string or list | raft-small-directories | Wordlist URL(s) or path(s). Multiple wordlists are merged with deduplication. |
| `lines` | int | 5000 | Use only the first N lines from the wordlist. |
| `max_depth` | int | 0 | Maximum directory depth for recursive fuzzing. 0 = root only. |
| `extensions` | string or list | (none) | File extensions to append (e.g., `php,asp,jsp`). |
| `ignore_case` | bool | false | Lowercase all wordlist entries (deduplicates case variants). |
| `rate` | int | 0 | Max requests per second. 0 = unlimited (subject to global `http_rate_limit`). |
| `concurrency` | int | 50 | Number of concurrent requests per URL being fuzzed. |
| `avoid_wafs` | bool | true | Skip URLs behind confirmed WAFs. |

## Presets

BBOT includes two presets for directory brute-forcing:

### `dirbust-light`

Surface-level directory discovery with a smaller wordlist. Good for quick scans.

- Wordlist: raft-small-directories (first 1000 lines)
- No extensions, no recursion
- WAF avoidance enabled

```bash
bbot -t example.com -p dirbust-light
```

### `dirbust-heavy`

Aggressive recursive brute-forcing with a large extension list. Includes spidering and wayback URL extraction to discover additional directories to fuzz. WAF avoidance is disabled so brute-forcing proceeds even against WAF-protected hosts.

- Wordlist: raft-small-directories (first 5000 lines)
- Extensions: php, asp, aspx, ashx, asmx, jsp, jspx, cfm, zip, conf, config, xml, json, yml, yaml
- Recursive to depth 3
- Includes spider and wayback modules
- `avoid_wafs` disabled

```bash
bbot -t example.com -p dirbust-heavy
```
