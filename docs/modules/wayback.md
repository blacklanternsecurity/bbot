# Wayback

## Overview

The Wayback module queries [archive.org's Wayback Machine](https://web.archive.org/) CDX API to discover subdomains, URLs, web parameters, and archived content for your targets. By default it operates as a passive subdomain enumeration source, but with its extended features enabled it becomes a powerful tool for discovering dead URLs, extracting parameters for fuzzing, and retrieving archived versions of pages that no longer exist.

* Watches: **DNS_NAME**, **URL**
* Produces: **URL_UNVERIFIED**, **DNS_NAME**, **WEB_PARAMETER**, **HTTP_RESPONSE**, **FINDING**
* Flags: `passive`, `subdomain-enum`, `safe`

## Default Behavior

By default, wayback only emits **DNS_NAME** events (subdomains) extracted from archived URLs. This is the behavior you get when wayback is included via the `subdomain-enum` preset. No URLs, parameters, or archived content are fetched.

To unlock the more advanced features, you need to enable them via configuration options or use one of the wayback presets.

## Configuration Options

| Option              | Type | Default | Description                                                                                           |
|---------------------|------|---------|-------------------------------------------------------------------------------------------------------|
| `urls`              | bool | `False` | Emit `URL_UNVERIFIED` events in addition to `DNS_NAME`s. Required for `parameters` and `archive`.     |
| `parameters`        | bool | `False` | Extract `WEB_PARAMETER` events from query strings in archived URLs. Requires `urls=True`.             |
| `archive`           | bool | `False` | Fetch archived versions of dead URLs and emit `HTTP_RESPONSE` events. Requires `urls=True`.           |
| `garbage_threshold` | int  | `10`    | Deduplicate similar URLs if they appear in groups of this size or larger. Lower = less noise.          |

## Features

### URL Discovery (`urls: True`)

When `urls` is enabled, wayback emits `URL_UNVERIFIED` events for every unique URL found in the Wayback Machine's index. These are tagged with `from-wayback` and sent through BBOT's normal URL verification pipeline (httpx).

Before emission, URLs go through several cleanup steps:

- **URL collapsing** - Groups of similar URLs (e.g. pagination, search results) are deduplicated based on the `garbage_threshold` setting
- **HTTP/HTTPS deduplication** - When both `http://` and `https://` variants exist, only the HTTPS version is kept
- **Blacklist filtering** - URLs containing known CDN/WAF paths (e.g. `_Incapsula_Resource`, `/cdn-cgi/`) are filtered out

### Parameter Extraction (`parameters: True`)

When `parameters` is enabled (requires `urls: True`), wayback extracts query string parameters from archived URLs and emits them as `WEB_PARAMETER` events. This is useful for discovering GET parameters that can be fed into fuzzing modules like lightfuzz.

Parameters are cached and only emitted after the corresponding URL has been verified as live by httpx. This prevents emitting parameters for URLs that no longer exist.

!!! note
    Parameter extraction requires at least one module that consumes `WEB_PARAMETER` events to be active (e.g. `lightfuzz`, `hunt`, `paramminer_getparams`). If no such module is present, parameter extraction is automatically disabled with a warning.

### Archive Retrieval (`archive: True`)

When `archive` is enabled (requires `urls: True`), wayback fetches the actual archived content of URLs from the Wayback Machine and emits them as `HTTP_RESPONSE` events. This is particularly useful for:

- **Finding secrets in dead pages** - Archived versions may contain API keys, credentials, or other sensitive data that modules like `badsecrets` can detect
- **Discovering hidden functionality** - Pages that have been removed may reveal application structure or endpoints

Archive retrieval runs during the module's `finish()` phase, after all URLs have been discovered and verified. URLs that are confirmed live (2xx status) are automatically removed from the archive queue, so only dead URLs are fetched from the archive.

The archived content goes through extensive cleanup to remove Wayback Machine artifacts:

- Wayback toolbar/header/footer HTML is stripped
- Rewritten URLs (e.g. `http://web.archive.org/web/20250101/http://example.com/page`) are restored to originals
- Wayback-injected headers (`x-archive-*`, `set-cookie`) are removed
- The event's host, port, and URL are set to the original target, not `web.archive.org`

Archived HTTP_RESPONSE events are tagged with `from-wayback` and `archived`.

!!! warning
    Static file extensions (images, CSS, JS, etc.) are automatically skipped during archive retrieval to avoid unnecessary traffic.

### Interesting File Detection

When `urls` is enabled, wayback also checks for potentially interesting archived files by looking for URLs with sensitive extensions: `.zip`, `.sql`, `.bak`, `.env`, `.config`, `.tar.gz`, `.tar.bz2`.

When found, these are verified with a HEAD request to archive.org. If the archived file exists and isn't a soft-404, a `FINDING` event is emitted with details about the file (including size if available). These findings are tagged with `from-wayback`, `archived`, and `interesting-file`.

## Presets

Wayback comes with two dedicated presets, and is also integrated into several other presets:

### `-p wayback`

Basic URL discovery mode. Includes `subdomain-enum` and enables `urls: True`. Good for general recon when you want to discover historical URLs alongside subdomains.

```bash
bbot -p wayback -t evilcorp.com
```

### `-p wayback-heavy`

Full-featured mode with URL discovery, parameter extraction, and archive retrieval. Also includes `badsecrets` to scan archived content for exposed secrets.

```bash
bbot -p wayback-heavy -t evilcorp.com
```

### Integration with other presets

Wayback's extended features are also enabled in several other presets:

| Preset                | Wayback Config                          |
|-----------------------|-----------------------------------------|
| `kitchen-sink`        | `urls`, `parameters`, `archive`         |
| `dirbust-heavy`       | `urls`                                  |
| `nuclei-intense`      | `urls`                                  |
| `lightfuzz-heavy`     | `urls`, `parameters`                    |
| `lightfuzz-superheavy`| `urls`, `parameters`, `archive`         |

## Example Commands

```bash
# Basic subdomain enumeration (default behavior, no URL emission)
bbot -p subdomain-enum -t evilcorp.com
```

```bash
# URL discovery via wayback preset
bbot -p wayback -t evilcorp.com
```

```bash
# Full wayback integration with archived content and parameter extraction
bbot -p wayback-heavy -t evilcorp.com
```

```bash
# Enable wayback URLs alongside a nuclei scan
bbot -p nuclei -m wayback -c modules.wayback.urls=True --allow-deadly -t evilcorp.com
```

```bash
# Pair with lightfuzz for parameter fuzzing using archived parameters
bbot -p lightfuzz-heavy spider -t evilcorp.com --allow-deadly
```

```bash
# Enable wayback features via command-line config
bbot -p subdomain-enum -c modules.wayback.urls=True modules.wayback.parameters=True modules.wayback.archive=True -t evilcorp.com
```

```bash
# Adjust garbage threshold for cleaner output (more aggressive deduplication)
bbot -p wayback -c modules.wayback.garbage_threshold=5 -t evilcorp.com
```
